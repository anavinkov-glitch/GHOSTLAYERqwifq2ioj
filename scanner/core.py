"""Scanner core.

``scan_pdf`` is the only function the rest of the app needs. It builds a
:class:`DocumentContext` (one pass over the file, everything the detectors
could want), runs every detector, scores the result and returns a plain
dict that is safe to store as JSON and render in a template.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import io
import logging
import os
import re
import time
from typing import Any

import pymupdf

from . import detectors as det
from . import patterns

log = logging.getLogger(__name__)

MAX_PAGES = 40
MAX_RENDER_PAGES = 6
RENDER_DPI = 110
SAMPLE_DPI = 72

VERDICTS = [
    (70, "poisoned", "Poisoned", "This document is carrying instructions written for a machine."),
    (35, "suspicious", "Suspicious", "There is hidden content here that a reader would never see."),
    (12, "review", "Worth a look", "Some oddities that are probably benign, but not certainly."),
    (0, "clean", "Clean", "Nothing hidden. What you see is what a model reads."),
]


# --------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------


class DocumentContext:
    """Everything the detectors read, gathered in one pass."""

    def __init__(self, doc: pymupdf.Document, filename: str = "document.pdf"):
        self.doc = doc
        self.filename = filename
        self.page_count = doc.page_count
        self.pages_scanned = min(doc.page_count, MAX_PAGES)

        self.spans_by_page: dict[int, list[dict]] = {}
        self.text_by_page: dict[int, str] = {}
        self.hidden_text_by_page: dict[int, str] = {}
        self.page_boxes: dict[int, pymupdf.Rect] = {}
        self.covers_by_page: dict[int, list[dict]] = {}
        self.annots_by_page: dict[int, list[dict]] = {}
        self.widgets_by_page: dict[int, list[dict]] = {}
        self.image_area_by_page: dict[int, float] = {}

        self._pixmaps: dict[int, pymupdf.Pixmap | None] = {}
        self._page_bg: dict[int, tuple[float, float, float]] = {}
        self._bg_cache: dict[tuple[int, int, int, int, int], tuple[float, float, float]] = {}

        self.metadata: dict[str, Any] = {}
        self.xmp: str = ""
        self.embedded_files: list[dict] = []
        self.active_content: list[dict] = []
        self.hidden_layers: set[str] = set()
        self.warnings: list[str] = []

        self._load_document_level()
        for page_no in range(self.pages_scanned):
            self._load_page(page_no)

    def text_sources(self) -> list[dict]:
        """Every channel whose text reaches a model, not just the page body.

        Character-level tricks are worth catching wherever they ride, and a
        payload in a metadata field or a form tooltip is extracted by most
        pipelines exactly like body text is.
        """
        sources: list[dict] = []
        for page_no, text in self.text_by_page.items():
            if text.strip():
                sources.append({"source": f"page {page_no + 1}", "page": page_no, "text": text})
        for key, value in (self.metadata or {}).items():
            if isinstance(value, str) and value.strip():
                sources.append({"source": f"metadata/{key}", "page": None, "text": value})
        if self.xmp.strip():
            sources.append({"source": "XMP metadata", "page": None, "text": self.xmp})
        for page_no, annots in self.annots_by_page.items():
            for annot in annots:
                blob = " ".join(
                    str(v) for v in (annot.get("content"), annot.get("title"), annot.get("subject")) if v
                )
                if blob.strip():
                    sources.append(
                        {"source": f"annotation on page {page_no + 1}", "page": page_no, "text": blob}
                    )
        for page_no, widgets in self.widgets_by_page.items():
            for widget in widgets:
                blob = " ".join(str(v) for v in (widget.get("value"), widget.get("tooltip")) if v)
                if blob.strip():
                    sources.append(
                        {"source": f"form field on page {page_no + 1}", "page": page_no, "text": blob}
                    )
        return sources

    # -- document level -----------------------------------------------------

    def _load_document_level(self) -> None:
        try:
            self.metadata = {k: v for k, v in (self.doc.metadata or {}).items() if v}
        except Exception as exc:  # pragma: no cover - defensive
            self.warnings.append(f"Could not read metadata: {exc}")

        try:
            self.xmp = self.doc.get_xml_metadata() or ""
        except Exception:
            self.xmp = ""

        try:
            for i in range(self.doc.embfile_count()):
                info = self.doc.embfile_info(i)
                self.embedded_files.append(
                    {
                        "name": info.get("filename") or info.get("name") or f"attachment_{i}",
                        "size": info.get("size", 0),
                        "desc": info.get("desc", ""),
                    }
                )
        except Exception:
            pass

        self._load_optional_content()
        self._load_active_content()

    def _load_optional_content(self) -> None:
        try:
            ocgs = self.doc.get_ocgs() or {}
        except Exception:
            return
        for _xref, info in ocgs.items():
            try:
                if info.get("on") is False:
                    name = (info.get("name") or "").strip()
                    if name:
                        self.hidden_layers.add(name)
            except Exception:
                continue

    def _load_active_content(self) -> None:
        """Look for JavaScript, open actions and automatic triggers."""
        try:
            catalog = self.doc.pdf_catalog()
        except Exception:
            return

        def key(path: str) -> str:
            try:
                kind, value = self.doc.xref_get_key(catalog, path)
                return "" if kind == "null" else str(value)
            except Exception:
                return ""

        open_action = key("OpenAction")
        if open_action:
            lowered = open_action.lower()
            if "javascript" in lowered or "/js" in lowered or "/launch" in lowered:
                self.active_content.append(
                    {
                        "title": "The document runs an action when it opens",
                        "technique": "/OpenAction",
                        "evidence": open_action,
                    }
                )

        names_js = key("Names/JavaScript")
        if names_js:
            self.active_content.append(
                {
                    "title": "Document-level JavaScript is present",
                    "technique": "/Names /JavaScript",
                    "evidence": names_js,
                }
            )

        aa = key("AA")
        if aa:
            self.active_content.append(
                {
                    "title": "Additional-actions trigger attached to the document",
                    "technique": "/AA",
                    "evidence": aa,
                }
            )

        # Catch JavaScript stored on individual objects too.
        try:
            js_objects = 0
            for xref in range(1, min(self.doc.xref_length(), 4000)):
                try:
                    if self.doc.xref_get_key(xref, "S")[1] == "/JavaScript":
                        js_objects += 1
                except Exception:
                    continue
            if js_objects and not any(a["technique"].endswith("JavaScript") for a in self.active_content):
                self.active_content.append(
                    {
                        "title": f"{js_objects} JavaScript action object(s) in the file",
                        "technique": "/S /JavaScript",
                        "evidence": f"{js_objects} objects",
                    }
                )
        except Exception:
            pass

    # -- page level ---------------------------------------------------------

    def _load_page(self, page_no: int) -> None:
        try:
            page = self.doc[page_no]
        except Exception as exc:
            self.warnings.append(f"Page {page_no + 1} could not be opened: {exc}")
            return

        try:
            box = page.rect & page.cropbox if page.cropbox else page.rect
            self.page_boxes[page_no] = pymupdf.Rect(box)
        except Exception:
            self.page_boxes[page_no] = pymupdf.Rect(page.rect)

        try:
            spans = page.get_texttrace() or []
        except Exception as exc:
            self.warnings.append(f"Page {page_no + 1} text trace failed: {exc}")
            spans = []
        self.spans_by_page[page_no] = spans

        try:
            self.covers_by_page[page_no] = self._collect_covers(page)
        except Exception:
            self.covers_by_page[page_no] = []

        try:
            self.image_area_by_page[page_no] = self._image_area(page)
        except Exception:
            self.image_area_by_page[page_no] = 0.0

        self._load_annots(page, page_no)
        self._load_widgets(page, page_no)
        self._classify_spans(page_no)

    def _collect_covers(self, page: pymupdf.Page) -> list[dict]:
        covers: list[dict] = []
        for drawing in page.get_drawings() or []:
            fill = drawing.get("fill")
            if fill is None:
                continue
            if (drawing.get("fill_opacity") or 1.0) < 0.95:
                continue
            rect = drawing.get("rect")
            if rect is None or rect.is_empty:
                continue
            covers.append(
                {
                    "rect": pymupdf.Rect(rect),
                    "seqno": drawing.get("seqno", 0),
                    "hex": det.to_hex(fill),
                    "fill": tuple(fill),
                }
            )
        # Images are deliberately left out. Their position in the draw order
        # is not recoverable here, and text sitting on top of a photo or a
        # logo is completely ordinary, so including them would flag a large
        # share of perfectly normal documents.
        return covers

    def _image_area(self, page: pymupdf.Page) -> float:
        page_area = abs(page.rect.get_area()) or 1.0
        total = 0.0
        for img in page.get_images(full=True) or []:
            try:
                for rect in page.get_image_rects(img[0]):
                    total += abs(pymupdf.Rect(rect).get_area())
            except Exception:
                continue
        return min(1.0, total / page_area)

    def _load_annots(self, page: pymupdf.Page, page_no: int) -> None:
        collected: list[dict] = []
        try:
            for annot in page.annots() or []:
                try:
                    info = annot.info or {}
                    flags = annot.flags or 0
                    collected.append(
                        {
                            "type": (annot.type or ["", "annotation"])[1],
                            "content": info.get("content", ""),
                            "title": info.get("title", ""),
                            "subject": info.get("subject", ""),
                            "hidden": bool(flags & 2),
                            "noview": bool(flags & 32),
                            "bbox": list(annot.rect),
                        }
                    )
                except Exception:
                    continue
        except Exception:
            pass
        if collected:
            self.annots_by_page[page_no] = collected

    def _load_widgets(self, page: pymupdf.Page, page_no: int) -> None:
        collected: list[dict] = []
        try:
            for widget in page.widgets() or []:
                try:
                    rect = pymupdf.Rect(widget.rect)
                    collected.append(
                        {
                            "name": widget.field_name,
                            "value": widget.field_value,
                            "tooltip": getattr(widget, "field_label", None) or "",
                            "hidden": bool((widget.field_flags or 0) & 2) or rect.get_area() < 1.0,
                            "bbox": list(rect),
                        }
                    )
                except Exception:
                    continue
        except Exception:
            pass
        if collected:
            self.widgets_by_page[page_no] = collected

    # -- hidden-span classification ----------------------------------------

    def _classify_spans(self, page_no: int) -> None:
        """Mark each span visible or hidden, and record why.

        One shared judgement keeps the report, the model view and the score
        consistent with each other.
        """
        box = self.page_boxes.get(page_no)
        covers = self.covers_by_page.get(page_no, [])
        visible_parts: list[str] = []
        hidden_parts: list[str] = []

        for span in self.spans_by_page.get(page_no, []):
            text = det.span_text(span)
            reasons: list[str] = []

            if span.get("type") == 3:
                reasons.append("no ink (render mode 3)")

            opacity = span.get("opacity")
            if opacity is not None and opacity <= 0.08:
                reasons.append(f"{opacity:.0%} opacity")

            size = det.effective_size(span)
            if 0 < size < 3.5:
                reasons.append(f"{size:.2f}pt type")

            bbox = span.get("bbox")
            if bbox and box is not None:
                rect = pymupdf.Rect(bbox)
                area = rect.get_area()
                if area > 0 and ((rect & box).get_area() / area) < 0.35:
                    reasons.append("outside the page")

            if span.get("type") != 3 and not is_transparent(span):
                bg = self.background_under(page_no, bbox)
                if bg is not None:
                    ratio = det.contrast_ratio(det.normalise_colour(span), bg)
                    if ratio < 1.6:
                        reasons.append(f"{ratio:.2f}:1 contrast")

            layer = (span.get("layer") or "").strip()
            if layer and layer in self.hidden_layers:
                reasons.append(f"layer \u201c{layer}\u201d is off")

            if bbox and covers:
                rect = pymupdf.Rect(bbox)
                area = rect.get_area()
                seq = span.get("seqno", 0)
                if area > 0:
                    for cover in covers:
                        if cover["seqno"] > seq and (rect & cover["rect"]).get_area() / area >= 0.92:
                            reasons.append("covered by an opaque shape")
                            break

            span["_hidden"] = bool(reasons)
            span["_reasons"] = reasons
            span["_text"] = text

            if text.strip():
                (hidden_parts if reasons else visible_parts).append(text)

        self.text_by_page[page_no] = "\n".join(visible_parts + hidden_parts)
        self.hidden_text_by_page[page_no] = "\n".join(hidden_parts)

    # -- background sampling -----------------------------------------------

    def _pixmap(self, page_no: int) -> pymupdf.Pixmap | None:
        if page_no in self._pixmaps:
            return self._pixmaps[page_no]
        pix = None
        try:
            page = self.doc[page_no]
            pix = page.get_pixmap(dpi=SAMPLE_DPI, alpha=False, annots=False)
            if pix.n not in (1, 3):
                pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
        except Exception as exc:
            log.debug("pixmap failed on page %s: %s", page_no, exc)
            pix = None
        self._pixmaps[page_no] = pix
        return pix

    def _pixel(self, pix: pymupdf.Pixmap, x: int, y: int) -> tuple[float, float, float] | None:
        try:
            value = pix.pixel(x, y)
        except Exception:
            return None
        if value is None:
            return None
        if len(value) == 1:
            g = value[0] / 255.0
            return (g, g, g)
        return (value[0] / 255.0, value[1] / 255.0, value[2] / 255.0)

    def page_background(self, page_no: int) -> tuple[float, float, float]:
        if page_no in self._page_bg:
            return self._page_bg[page_no]
        bg = (1.0, 1.0, 1.0)
        pix = self._pixmap(page_no)
        if pix is not None and pix.width > 4 and pix.height > 4:
            counter: collections.Counter = collections.Counter()
            step_x = max(1, pix.width // 40)
            step_y = max(1, pix.height // 40)
            for y in range(0, pix.height, step_y):
                for x in range(0, pix.width, step_x):
                    px = self._pixel(pix, x, y)
                    if px is not None:
                        counter[tuple(round(c, 2) for c in px)] += 1
            if counter:
                bg = counter.most_common(1)[0][0]  # type: ignore[assignment]
        self._page_bg[page_no] = bg
        return bg

    def background_under(self, page_no: int, bbox) -> tuple[float, float, float] | None:
        """Modal colour of the pixels under ``bbox``.

        Glyphs cover a minority of the pixels in their own bounding box, so
        the most common colour there is the surface the text sits on. That
        is what makes white-on-dark-banner text safe from a false positive.
        """
        if not bbox:
            return self.page_background(page_no)
        pix = self._pixmap(page_no)
        if pix is None:
            return self.page_background(page_no)

        try:
            page = self.doc[page_no]
            rect = pymupdf.Rect(bbox)
            if page.rotation:
                rect = rect * page.rotation_matrix
            origin = page.rect
            scale = SAMPLE_DPI / 72.0
            x0 = int((rect.x0 - origin.x0) * scale) - 2
            y0 = int((rect.y0 - origin.y0) * scale) - 2
            x1 = int((rect.x1 - origin.x0) * scale) + 2
            y1 = int((rect.y1 - origin.y0) * scale) + 2
        except Exception:
            return self.page_background(page_no)

        x0, y0 = max(0, x0), max(0, y0)
        x1, y1 = min(pix.width, x1), min(pix.height, y1)
        if x1 - x0 < 1 or y1 - y0 < 1:
            return self.page_background(page_no)

        cache_key = (page_no, x0, y0, x1, y1)
        if cache_key in self._bg_cache:
            return self._bg_cache[cache_key]

        counter: collections.Counter = collections.Counter()
        step_x = max(1, (x1 - x0) // 24)
        step_y = max(1, (y1 - y0) // 12)
        for y in range(y0, y1, step_y):
            for x in range(x0, x1, step_x):
                px = self._pixel(pix, x, y)
                if px is not None:
                    counter[tuple(round(c, 2) for c in px)] += 1

        result = counter.most_common(1)[0][0] if counter else self.page_background(page_no)
        self._bg_cache[cache_key] = result  # type: ignore[assignment]
        return result  # type: ignore[return-value]

    def page_is_scanned(self, page_no: int) -> bool:
        return self.image_area_by_page.get(page_no, 0.0) > 0.6

    # -- derived views ------------------------------------------------------

    def model_view(self, page_no: int) -> list[dict]:
        """Extracted text in reading order, each run marked visible or not."""
        spans = [s for s in self.spans_by_page.get(page_no, []) if (s.get("_text") or "").strip()]
        spans.sort(key=lambda s: (round((s.get("bbox") or [0, 0, 0, 0])[1], 1),
                                  round((s.get("bbox") or [0, 0, 0, 0])[0], 1)))
        runs: list[dict] = []
        for span in spans:
            runs.append(
                {
                    "text": span.get("_text", ""),
                    "hidden": bool(span.get("_hidden")),
                    "reasons": span.get("_reasons", []),
                    "size": round(det.effective_size(span), 2),
                    "bbox": [round(v, 2) for v in (span.get("bbox") or [])],
                }
            )
        return runs

    def overlays(self, page_no: int) -> list[dict]:
        """Hidden spans as percentage boxes, for drawing on the page image."""
        box = self.page_boxes.get(page_no)
        if box is None or box.get_area() <= 0:
            return []
        width = box.width or 1
        height = box.height or 1
        out = []
        for span in self.spans_by_page.get(page_no, []):
            if not span.get("_hidden") or not (span.get("_text") or "").strip():
                continue
            bbox = span.get("bbox")
            if not bbox:
                continue
            out.append(
                {
                    "left": round(max(0.0, (bbox[0] - box.x0) / width) * 100, 3),
                    "top": round(max(0.0, (bbox[1] - box.y0) / height) * 100, 3),
                    "width": round(min(1.0, (bbox[2] - bbox[0]) / width) * 100, 3),
                    "height": round(min(1.0, (bbox[3] - bbox[1]) / height) * 100, 3),
                    "reasons": span.get("_reasons", []),
                    "text": det._clip(span.get("_text", ""), 160),
                }
            )
        return out

    def render_page(self, page_no: int) -> str | None:
        """Page as a base64 PNG, so a saved report needs no side files."""
        try:
            page = self.doc[page_no]
            pix = page.get_pixmap(dpi=RENDER_DPI, alpha=False)
            return base64.b64encode(pix.tobytes("png")).decode("ascii")
        except Exception as exc:
            log.debug("render failed on page %s: %s", page_no, exc)
            return None


def is_transparent(span: dict) -> bool:
    opacity = span.get("opacity")
    return opacity is not None and opacity <= 0.08


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def score_findings(findings: list[det.Finding]) -> int:
    """0-100 risk, with repeats of the same technique worth less each time.

    Twenty invisible spans are one attack, not twenty, so the second hit of
    a code counts 40% and the rest 15%.
    """
    by_code: dict[str, list[det.Finding]] = collections.defaultdict(list)
    for finding in findings:
        by_code[finding.code].append(finding)

    total = 0.0
    for group in by_code.values():
        group.sort(key=lambda f: det.SEVERITY_ORDER[f.severity])
        for index, finding in enumerate(group):
            factor = 1.0 if index == 0 else (0.4 if index == 1 else 0.15)
            total += finding.weight * factor
    return int(min(100, round(total)))


def verdict_for(score: int) -> dict:
    for threshold, key, label, blurb in VERDICTS:
        if score >= threshold:
            return {"key": key, "label": label, "blurb": blurb, "score": score}
    return {"key": "clean", "label": "Clean", "blurb": VERDICTS[-1][3], "score": score}


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def scan_bytes(data: bytes, filename: str = "document.pdf", render: bool = True) -> dict:
    started = time.perf_counter()
    sha = hashlib.sha256(data).hexdigest()

    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        return _error_result(filename, sha, len(data), f"This file could not be opened as a PDF: {exc}")

    try:
        if doc.needs_pass:
            if not doc.authenticate(""):
                doc.close()
                return _error_result(
                    filename, sha, len(data),
                    "The PDF is password protected, so its contents cannot be inspected.",
                )

        ctx = DocumentContext(doc, filename=filename)

        findings: list[det.Finding] = []
        detector_runs: list[dict] = []
        for name, func in det.ALL_DETECTORS:
            t0 = time.perf_counter()
            try:
                produced = func(ctx) or []
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("detector %s failed", name)
                produced = []
                ctx.warnings.append(f"Detector {name} failed: {exc}")
            findings.extend(produced)
            detector_runs.append(
                {
                    "name": name,
                    "label": name.replace("_", " ").capitalize(),
                    "info": det.DETECTOR_INFO.get(name, ""),
                    "hits": len(produced),
                    "ms": round((time.perf_counter() - t0) * 1000, 1),
                }
            )

        findings.sort(key=lambda f: (det.SEVERITY_ORDER[f.severity], f.page or 0, f.code))
        score = score_findings(findings)
        verdict = verdict_for(score)

        pages: list[dict] = []
        for page_no in range(ctx.pages_scanned):
            pages.append(
                {
                    "number": page_no + 1,
                    "image": ctx.render_page(page_no) if (render and page_no < MAX_RENDER_PAGES) else None,
                    "overlays": ctx.overlays(page_no),
                    "model_view": ctx.model_view(page_no),
                    "hidden_chars": len(re.sub(r"\s", "", ctx.hidden_text_by_page.get(page_no, ""))),
                    "total_chars": len(re.sub(r"\s", "", ctx.text_by_page.get(page_no, ""))),
                }
            )

        hidden_total = sum(p["hidden_chars"] for p in pages)
        char_total = sum(p["total_chars"] for p in pages)
        span_total = sum(len(v) for v in ctx.spans_by_page.values())
        hidden_spans = sum(1 for v in ctx.spans_by_page.values() for s in v if s.get("_hidden"))

        counts = collections.Counter(f.severity for f in findings)
        result = {
            "ok": True,
            "filename": filename,
            "sha256": sha,
            "bytes": len(data),
            "scanned_at": int(time.time()),
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            "verdict": verdict,
            "score": score,
            "findings": [f.to_dict() for f in findings],
            "counts": {
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0),
                "total": len(findings),
            },
            "stats": {
                "pages": ctx.page_count,
                "pages_scanned": ctx.pages_scanned,
                "spans": span_total,
                "hidden_spans": hidden_spans,
                "chars": char_total,
                "hidden_chars": hidden_total,
                "hidden_share": round(hidden_total / char_total, 4) if char_total else 0.0,
            },
            "metadata": ctx.metadata,
            "detectors": detector_runs,
            "pages": pages,
            "hidden_text": "\n".join(
                v for v in (ctx.hidden_text_by_page.get(i, "") for i in range(ctx.pages_scanned)) if v.strip()
            ),
            "warnings": ctx.warnings,
        }
        return result
    finally:
        try:
            doc.close()
        except Exception:
            pass


def scan_path(path: str, render: bool = True) -> dict:
    with open(path, "rb") as fh:
        return scan_bytes(fh.read(), filename=os.path.basename(path), render=render)


def _error_result(filename: str, sha: str, size: int, message: str) -> dict:
    return {
        "ok": False,
        "error": message,
        "filename": filename,
        "sha256": sha,
        "bytes": size,
        "scanned_at": int(time.time()),
        "duration_ms": 0.0,
        "verdict": {"key": "error", "label": "Unreadable", "blurb": message, "score": 0},
        "score": 0,
        "findings": [],
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        "stats": {"pages": 0, "pages_scanned": 0, "spans": 0, "hidden_spans": 0,
                  "chars": 0, "hidden_chars": 0, "hidden_share": 0.0},
        "metadata": {},
        "detectors": [],
        "pages": [],
        "hidden_text": "",
        "warnings": [],
    }
