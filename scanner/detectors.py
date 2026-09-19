"""The detectors.

Each detector takes a :class:`~ghostlayer.scanner.core.DocumentContext`
(or a single page context) and returns a list of :class:`Finding`.
Detectors never raise: a detector that cannot run records an ``info``
finding and moves on, so one malformed object in a PDF never costs you
the rest of the report.
"""

from __future__ import annotations

import collections
import dataclasses
import re
import unicodedata
from typing import Any, Iterable

import pymupdf

from . import patterns

# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 34, "high": 20, "medium": 9, "low": 3, "info": 0}


@dataclasses.dataclass
class Finding:
    """One thing worth telling the user about."""

    code: str
    detector: str
    severity: str
    title: str
    detail: str
    technique: str
    evidence: str = ""
    page: int | None = None
    bbox: list[float] | None = None
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["weight"] = self.weight
        return d


def _clip(text: str, limit: int = 400) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "\u2026"


# --------------------------------------------------------------------------
# Colour maths
# --------------------------------------------------------------------------


def _srgb_to_linear(c: float) -> float:
    c = max(0.0, min(1.0, c))
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb: Iterable[float]) -> float:
    r, g, b = (list(rgb) + [0.0, 0.0, 0.0])[:3]
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def contrast_ratio(fg: Iterable[float], bg: Iterable[float]) -> float:
    l1, l2 = relative_luminance(fg), relative_luminance(bg)
    if l1 < l2:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)


def to_hex(rgb: Iterable[float]) -> str:
    r, g, b = (list(rgb) + [0.0, 0.0, 0.0])[:3]
    return "#%02X%02X%02X" % (
        int(round(max(0.0, min(1.0, r)) * 255)),
        int(round(max(0.0, min(1.0, g)) * 255)),
        int(round(max(0.0, min(1.0, b)) * 255)),
    )


def normalise_colour(span: dict) -> tuple[float, float, float]:
    """PyMuPDF reports colour in the span's own colourspace. Fold the
    greyscale and CMYK cases down to RGB so one comparison works for all."""
    colour = list(span.get("color") or [0.0, 0.0, 0.0])
    space = span.get("colorspace", len(colour))
    if space == 1 or len(colour) == 1:
        g = colour[0]
        return (g, g, g)
    if space == 4 or len(colour) == 4:
        c, m, y, k = colour[:4]
        return (
            max(0.0, 1.0 - min(1.0, c + k)),
            max(0.0, 1.0 - min(1.0, m + k)),
            max(0.0, 1.0 - min(1.0, y + k)),
        )
    return tuple((colour + [0.0, 0.0, 0.0])[:3])  # type: ignore[return-value]


# --------------------------------------------------------------------------
# Span helpers
# --------------------------------------------------------------------------


def span_text(span: dict) -> str:
    return "".join(chr(c[0]) if isinstance(c[0], int) else str(c[0]) for c in span.get("chars", []))


def effective_size(span: dict) -> float:
    """Rendered size in points.

    ``size`` is the font size before the text matrix is applied, so a
    document can set a normal size and then scale it to nothing. The bbox
    reflects what actually lands on the page, so prefer it.
    """
    declared = float(span.get("size") or 0.0)
    bbox = span.get("bbox")
    asc = float(span.get("ascender") or 0.0)
    desc = float(span.get("descender") or 0.0)
    if bbox and asc - desc > 0.01:
        height = abs(bbox[3] - bbox[1])
        measured = height / (asc - desc)
        if measured > 0:
            return min(declared, measured) if declared else measured
    return declared


def is_blank(text: str) -> bool:
    return not text.strip()


# --------------------------------------------------------------------------
# Detectors — hidden rendering
# --------------------------------------------------------------------------


def detect_invisible_render_mode(ctx) -> list[Finding]:
    """Text render mode 3 (and 7) paints nothing at all.

    There is no legitimate reason for a résumé to carry it. The one common
    benign use is the OCR layer under a scanned page, so a document that is
    mostly image gets a softer verdict.
    """
    out: list[Finding] = []
    for page_no, spans in ctx.spans_by_page.items():
        ocr_like = ctx.page_is_scanned(page_no)
        for span in spans:
            if span.get("type") != 3:
                continue
            text = span_text(span)
            if is_blank(text):
                continue
            severity = "low" if ocr_like else "critical"
            detail = (
                "The text is painted in render mode 3, which draws no pixels. "
                "It is absent from the printed page and from any screenshot, but "
                "every PDF text extractor returns it verbatim."
            )
            if ocr_like:
                detail += (
                    " This page is mostly image, so the invisible layer is most "
                    "likely ordinary OCR output rather than an attack."
                )
            out.append(
                Finding(
                    code="invisible_render_mode",
                    detector="Invisible render mode",
                    severity=severity,
                    title="Text painted with no ink",
                    detail=detail,
                    technique="Render mode 3",
                    evidence=_clip(text),
                    page=page_no,
                    bbox=list(span.get("bbox") or []),
                    extra={"font": span.get("font"), "size": round(effective_size(span), 2)},
                )
            )
    return out


def detect_transparent_text(ctx) -> list[Finding]:
    """Fill opacity at or near zero: visually absent, textually present."""
    out: list[Finding] = []
    for page_no, spans in ctx.spans_by_page.items():
        for span in spans:
            opacity = span.get("opacity")
            if opacity is None or opacity > 0.08:
                continue
            text = span_text(span)
            if is_blank(text):
                continue
            out.append(
                Finding(
                    code="transparent_text",
                    detector="Transparent text",
                    severity="critical" if opacity <= 0.02 else "high",
                    title=f"Text drawn at {opacity:.0%} opacity",
                    detail=(
                        "The glyphs are drawn, but with an alpha low enough that "
                        "nothing shows on screen or in print. Extraction ignores "
                        "opacity entirely."
                    ),
                    technique="Graphics state alpha",
                    evidence=_clip(text),
                    page=page_no,
                    bbox=list(span.get("bbox") or []),
                    extra={"opacity": round(float(opacity), 3)},
                )
            )
    return out


def detect_low_contrast_text(ctx) -> list[Finding]:
    """White-on-white and its near neighbours.

    The background is measured, not assumed: the modal colour of the pixels
    under the span is the page beneath it, so white text on a dark banner
    is correctly left alone.
    """
    out: list[Finding] = []
    for page_no, spans in ctx.spans_by_page.items():
        for span in spans:
            if span.get("type") == 3:
                continue  # already reported by the render-mode detector
            text = span_text(span)
            if is_blank(text):
                continue
            fg = normalise_colour(span)
            bg = ctx.background_under(page_no, span.get("bbox"))
            if bg is None:
                continue
            ratio = contrast_ratio(fg, bg)
            if ratio >= 1.6:
                continue
            severity = "critical" if ratio < 1.12 else ("high" if ratio < 1.35 else "medium")
            out.append(
                Finding(
                    code="low_contrast_text",
                    detector="Low-contrast text",
                    severity=severity,
                    title=f"Text at {ratio:.2f}:1 against its background",
                    detail=(
                        f"The fill colour {to_hex(fg)} sits on a measured background of "
                        f"{to_hex(bg)}. Readable body text needs about 4.5:1. Below "
                        "roughly 1.2:1 the text is invisible to a reader while remaining "
                        "fully legible to an extractor."
                    ),
                    technique="Colour camouflage",
                    evidence=_clip(text),
                    page=page_no,
                    bbox=list(span.get("bbox") or []),
                    extra={
                        "ratio": round(ratio, 3),
                        "fg": to_hex(fg),
                        "bg": to_hex(bg),
                        "size": round(effective_size(span), 2),
                    },
                )
            )
    return out


def detect_micro_type(ctx) -> list[Finding]:
    """Type too small to resolve on paper but perfectly extractable."""
    out: list[Finding] = []
    for page_no, spans in ctx.spans_by_page.items():
        for span in spans:
            if span.get("type") == 3:
                continue
            size = effective_size(span)
            if size <= 0 or size >= 3.5:
                continue
            text = span_text(span)
            if is_blank(text) or len(text.strip()) < 4:
                continue
            out.append(
                Finding(
                    code="micro_type",
                    detector="Micro type",
                    severity="critical" if size < 2.0 else "high",
                    title=f"Text set at {size:.2f}pt",
                    detail=(
                        "Body text runs 9-12pt. Below about 3pt the glyphs collapse "
                        "into a grey smear at screen resolution and vanish on print, "
                        "but the characters are unchanged in the text layer."
                    ),
                    technique="Sub-legible font size",
                    evidence=_clip(text),
                    page=page_no,
                    bbox=list(span.get("bbox") or []),
                    extra={"size": round(size, 2), "font": span.get("font")},
                )
            )
    return out


def detect_offpage_text(ctx) -> list[Finding]:
    """Glyphs positioned outside the visible page box."""
    out: list[Finding] = []
    for page_no, spans in ctx.spans_by_page.items():
        box = ctx.page_boxes.get(page_no)
        if box is None:
            continue
        for span in spans:
            bbox = span.get("bbox")
            if not bbox:
                continue
            text = span_text(span)
            if is_blank(text):
                continue
            rect = pymupdf.Rect(bbox)
            if rect.is_empty:
                continue
            visible = rect & box
            covered = (visible.get_area() / rect.get_area()) if rect.get_area() > 0 else 1.0
            if covered >= 0.35:
                continue
            out.append(
                Finding(
                    code="offpage_text",
                    detector="Off-page text",
                    severity="critical" if covered < 0.02 else "high",
                    title="Text placed outside the page boundary",
                    detail=(
                        "The glyphs are positioned beyond the crop box, so no viewer "
                        "renders them and no printer prints them. Extraction walks the "
                        "content stream rather than the visible area, so it reads them."
                    ),
                    technique="Off-canvas positioning",
                    evidence=_clip(text),
                    page=page_no,
                    bbox=list(bbox),
                    extra={"visible_fraction": round(covered, 3), "page_box": list(box)},
                )
            )
    return out


def detect_covered_text(ctx) -> list[Finding]:
    """Text painted first, then buried under an opaque shape or image."""
    out: list[Finding] = []
    for page_no, spans in ctx.spans_by_page.items():
        covers = ctx.covers_by_page.get(page_no, [])
        if not covers:
            continue
        for span in spans:
            bbox = span.get("bbox")
            if not bbox or span.get("type") == 3:
                continue
            text = span_text(span)
            if is_blank(text):
                continue
            rect = pymupdf.Rect(bbox)
            if rect.is_empty or rect.get_area() <= 0:
                continue
            span_seq = span.get("seqno", 0)
            for cover in covers:
                if cover["seqno"] <= span_seq:
                    continue
                overlap = rect & cover["rect"]
                if overlap.get_area() / rect.get_area() < 0.92:
                    continue
                out.append(
                    Finding(
                        code="covered_text",
                        detector="Buried text",
                        severity="high",
                        title="Text painted over by an opaque shape",
                        detail=(
                            "The text is drawn, then an opaque block is drawn on top of "
                            "it. The page looks clean. Extractors read the content "
                            "stream in order and never apply the occlusion."
                        ),
                        technique="Z-order occlusion",
                        evidence=_clip(text),
                        page=page_no,
                        bbox=list(bbox),
                        extra={"cover_fill": cover.get("hex"), "cover_rect": list(cover["rect"])},
                    )
                )
                break
    return out


def detect_hidden_layers(ctx) -> list[Finding]:
    """Optional content groups switched off by default."""
    out: list[Finding] = []
    if not ctx.hidden_layers:
        return out
    for page_no, spans in ctx.spans_by_page.items():
        for span in spans:
            layer = (span.get("layer") or "").strip()
            if not layer or layer not in ctx.hidden_layers:
                continue
            text = span_text(span)
            if is_blank(text):
                continue
            out.append(
                Finding(
                    code="hidden_layer",
                    detector="Hidden layer",
                    severity="high",
                    title=f"Text on the disabled layer \u201c{layer}\u201d",
                    detail=(
                        "The document defines an optional content group that is off by "
                        "default, so viewers hide it. Most extraction pipelines flatten "
                        "every layer regardless of its visibility state."
                    ),
                    technique="Optional content group",
                    evidence=_clip(text),
                    page=page_no,
                    bbox=list(span.get("bbox") or []),
                    extra={"layer": layer},
                )
            )
    return out


# --------------------------------------------------------------------------
# Detectors — payload carriers outside the page content
# --------------------------------------------------------------------------


def detect_metadata_payload(ctx) -> list[Finding]:
    """Injection text parked in document metadata or XMP."""
    out: list[Finding] = []
    fields = dict(ctx.metadata or {})
    if ctx.xmp:
        fields["xmp"] = ctx.xmp
    for key, value in fields.items():
        if not isinstance(value, str) or not value.strip():
            continue
        hits = patterns.find_injection_hits(value)
        if not hits:
            continue
        top = hits[0]
        out.append(
            Finding(
                code="metadata_payload",
                detector="Metadata payload",
                severity="critical" if top["weight"] >= patterns.INJECTION_CONFIRM_SCORE else "medium",
                title=f"Instruction text in the {key} field",
                detail=(
                    "Document metadata is never shown in the body of the page, but "
                    "many extraction pipelines prepend it to the text they hand the "
                    "model as helpful context."
                ),
                technique="Metadata field",
                evidence=_clip(value),
                page=None,
                extra={"field": key, "hits": hits[:4]},
            )
        )
    return out


def detect_annotation_payload(ctx) -> list[Finding]:
    """Hidden annotations, and annotation text carrying instructions."""
    out: list[Finding] = []
    for page_no, annots in ctx.annots_by_page.items():
        for annot in annots:
            text = " ".join(
                str(v) for v in (annot.get("content"), annot.get("title"), annot.get("subject")) if v
            ).strip()
            hidden = annot.get("hidden") or annot.get("noview")
            hits = patterns.find_injection_hits(text) if text else []
            if not hits and not (hidden and text):
                continue
            severity = "critical" if hits and hidden else ("high" if hits else "medium")
            out.append(
                Finding(
                    code="annotation_payload",
                    detector="Annotation payload",
                    severity=severity,
                    title=(
                        "Hidden annotation carrying text"
                        if hidden
                        else f"Instruction text in a {annot.get('type', 'annotation')}"
                    ),
                    detail=(
                        "Annotation contents sit outside the page content stream. "
                        "A viewer can hide them with a single flag, while extraction "
                        "libraries commonly append them to the page text."
                    ),
                    technique="Annotation" + (" (hidden flag)" if hidden else ""),
                    evidence=_clip(text),
                    page=page_no,
                    bbox=annot.get("bbox"),
                    extra={"type": annot.get("type"), "hidden": bool(hidden), "hits": hits[:4]},
                )
            )
    return out


def detect_form_field_payload(ctx) -> list[Finding]:
    """AcroForm values and tooltips are extracted but rarely displayed."""
    out: list[Finding] = []
    for page_no, widgets in ctx.widgets_by_page.items():
        for widget in widgets:
            text = " ".join(
                str(v) for v in (widget.get("value"), widget.get("tooltip")) if v
            ).strip()
            if not text:
                continue
            hits = patterns.find_injection_hits(text)
            if not hits and not widget.get("hidden"):
                continue
            out.append(
                Finding(
                    code="form_field_payload",
                    detector="Form field payload",
                    severity="high" if hits else "low",
                    title=f"Text in the form field \u201c{widget.get('name') or 'unnamed'}\u201d",
                    detail=(
                        "Form field values and tooltips travel with the document and "
                        "are picked up by most parsers, even when the widget itself is "
                        "set to hidden or sized to nothing."
                    ),
                    technique="AcroForm field",
                    evidence=_clip(text),
                    page=page_no,
                    bbox=widget.get("bbox"),
                    extra={"field": widget.get("name"), "hidden": widget.get("hidden"), "hits": hits[:4]},
                )
            )
    return out


def detect_embedded_files(ctx) -> list[Finding]:
    out: list[Finding] = []
    for entry in ctx.embedded_files:
        out.append(
            Finding(
                code="embedded_file",
                detector="Embedded file",
                severity="medium",
                title=f"Attachment \u201c{entry['name']}\u201d travels inside the PDF",
                detail=(
                    "An attached file rides along invisibly. It is a common way to "
                    "carry a second-stage payload past a filter that only inspects the "
                    "page text."
                ),
                technique="Embedded file stream",
                evidence=f"{entry['name']} \u2014 {entry.get('size', 0)} bytes",
                page=None,
                extra=entry,
            )
        )
    return out


def detect_active_content(ctx) -> list[Finding]:
    out: list[Finding] = []
    for entry in ctx.active_content:
        out.append(
            Finding(
                code="active_content",
                detector="Active content",
                severity="high",
                title=entry["title"],
                detail=(
                    "The document asks the reader to run something or go somewhere the "
                    "moment it opens. No document that is only meant to be read needs "
                    "this."
                ),
                technique=entry["technique"],
                evidence=_clip(entry.get("evidence", "")),
                page=None,
                extra=entry,
            )
        )
    return out


# --------------------------------------------------------------------------
# Detectors — character-level tricks
# --------------------------------------------------------------------------


def detect_invisible_unicode(ctx) -> list[Finding]:
    """Zero-width characters, bidi overrides and Unicode Tag smuggling."""
    out: list[Finding] = []
    for source in ctx.text_sources():
        text, page_no, where = source["text"], source["page"], source["source"]
        counts = collections.Counter(ch for ch in text if ch in patterns.INVISIBLE_CHARS)
        if counts:
            names = ", ".join(f"{patterns.INVISIBLE_CHARS[c]} \u00d7{n}" for c, n in counts.most_common(4))
            total = sum(counts.values())
            out.append(
                Finding(
                    code="invisible_unicode",
                    detector="Zero-width characters",
                    severity="medium" if total < 12 else "high",
                    title=f"{total} zero-width characters in {where}",
                    detail=(
                        "These code points occupy no space on the page but survive "
                        "extraction intact. They are used both to smuggle content and "
                        "to break keyword filters by splitting words invisibly."
                    ),
                    technique="Zero-width Unicode",
                    evidence=names,
                    page=page_no,
                    extra={
                        "where": where,
                        "counts": {patterns.INVISIBLE_CHARS[c]: n for c, n in counts.items()},
                    },
                )
            )

        bidi = collections.Counter(ch for ch in text if ch in patterns.BIDI_CHARS)
        if bidi:
            out.append(
                Finding(
                    code="bidi_override",
                    detector="Bidirectional override",
                    severity="high",
                    title="Bidirectional control characters present",
                    detail=(
                        "Direction overrides let the rendered order of a line differ "
                        "from its stored order, so what a person reads and what a "
                        "parser reads can be two different sentences."
                    ),
                    technique="Unicode bidi override",
                    evidence=", ".join(f"{patterns.BIDI_CHARS[c]} \u00d7{n}" for c, n in bidi.most_common(4)),
                    page=page_no,
                    extra={
                        "where": where,
                        "counts": {patterns.BIDI_CHARS[c]: n for c, n in bidi.items()},
                    },
                )
            )

        tag_chars = [ch for ch in text if patterns.TAG_RANGE[0] <= ord(ch) <= patterns.TAG_RANGE[1]]
        if tag_chars:
            decoded = patterns.decode_tag_chars(text)
            out.append(
                Finding(
                    code="tag_smuggling",
                    detector="Unicode tag smuggling",
                    severity="critical",
                    title="Hidden ASCII encoded in Unicode Tag characters",
                    detail=(
                        "The Tag block maps one-to-one onto ASCII and renders as "
                        "absolutely nothing. A full paragraph of instructions can hide "
                        "behind what looks like a single word."
                    ),
                    technique="Unicode Tag block (U+E0000)",
                    evidence=_clip(decoded) or f"{len(tag_chars)} tag characters",
                    page=page_no,
                    extra={"where": where, "decoded": _clip(decoded, 1000), "count": len(tag_chars)},
                )
            )
    return out


def detect_homoglyphs(ctx) -> list[Finding]:
    """Mixed-script tokens, with links and addresses weighted higher."""
    out: list[Finding] = []
    for source in ctx.text_sources():
        text, page_no, where = source["text"], source["page"], source["source"]
        suspects: list[tuple[str, str, bool]] = []
        targets = set(patterns.URL_RE.findall(text)) | set(patterns.EMAIL_RE.findall(text))
        for token in re.findall(r"\S{4,}", text):
            confusables = [ch for ch in token if ch in patterns.HOMOGLYPHS]
            if not confusables:
                continue
            has_latin = any("a" <= ch.lower() <= "z" for ch in token)
            if not has_latin:
                continue  # a wholly non-Latin word is just another language
            folded = "".join(patterns.HOMOGLYPHS.get(ch, ch) for ch in token)
            is_target = token in targets or any(token in t for t in targets)
            suspects.append((token, folded, is_target))
        if not suspects:
            continue
        linked = [s for s in suspects if s[2]]
        shown = (linked or suspects)[:5]
        out.append(
            Finding(
                code="homoglyph",
                detector="Look-alike characters",
                severity="high" if linked else "medium",
                title=(
                    "A link or address is built from look-alike characters"
                    if linked
                    else f"{len(suspects)} words mix scripts"
                ),
                detail=(
                    "Cyrillic and Greek letters that are visually identical to Latin "
                    "ones make a spoofed domain indistinguishable on the page. Reading "
                    "the bytes rather than the shapes tells them apart."
                ),
                technique="Homoglyph substitution",
                evidence="; ".join(f"{t} \u2192 reads as {f}" for t, f, _ in shown),
                page=page_no,
                extra={
                    "where": where,
                    "tokens": [{"as_written": t, "folded": f, "in_link": l} for t, f, l in shown],
                },
            )
        )
    return out


# --------------------------------------------------------------------------
# Detector — the payload itself
# --------------------------------------------------------------------------


def detect_injection_language(ctx) -> list[Finding]:
    """Language addressed to a model rather than a reader.

    Scored twice: once against everything extracted, and again, harder,
    against the spans that some other detector already found to be hidden.
    Concealment plus instruction is the combination that matters.
    """
    out: list[Finding] = []

    for page_no, text in ctx.text_by_page.items():
        hits = patterns.find_injection_hits(text)
        if not hits:
            continue
        hidden_text = ctx.hidden_text_by_page.get(page_no, "")
        hidden_hits = patterns.find_injection_hits(hidden_text) if hidden_text else []

        if hidden_hits:
            top = hidden_hits[0]
            out.append(
                Finding(
                    code="injection_hidden",
                    detector="Prompt injection",
                    severity="critical",
                    title=f"Hidden instruction to the model: {top['label'].lower()}",
                    detail=(
                        "This phrasing is aimed at a language model, and it was placed "
                        "where a person cannot see it. Concealment is what separates a "
                        "confused sentence from a deliberate attack."
                    ),
                    technique="Concealed instruction",
                    evidence=_clip(top["match"], 300),
                    page=page_no,
                    extra={
                        "hits": hidden_hits[:8],
                        "score": sum(h["weight"] for h in hidden_hits),
                        "full": _clip(hidden_text, 2000),
                    },
                )
            )

        visible_only = [h for h in hits if h["match"] not in hidden_text]
        if visible_only:
            top = visible_only[0]
            severity = (
                "high"
                if top["weight"] >= patterns.INJECTION_CONFIRM_SCORE
                else ("medium" if top["weight"] >= patterns.INJECTION_SUSPECT_SCORE else "low")
            )
            out.append(
                Finding(
                    code="injection_visible",
                    detector="Prompt injection",
                    severity=severity,
                    title=f"Instruction-shaped text on the page: {top['label'].lower()}",
                    detail=(
                        "The phrasing matches known prompt-injection templates, but it "
                        "sits in plain sight. Treat it as worth a human glance rather "
                        "than proof of intent \u2014 a document about prompt injection will "
                        "trip this too."
                    ),
                    technique="Visible instruction text",
                    evidence=_clip(top["match"], 300),
                    page=page_no,
                    extra={"hits": visible_only[:8]},
                )
            )
    return out


def detect_text_layer_mismatch(ctx) -> list[Finding]:
    """A large gap between what is rendered and what is extractable.

    Catches hiding techniques nothing else has a rule for: if a page shows
    two paragraphs and yields eight, something is carrying the difference.
    """
    out: list[Finding] = []
    for page_no in ctx.text_by_page:
        total = len(re.sub(r"\s", "", ctx.text_by_page.get(page_no, "")))
        hidden = len(re.sub(r"\s", "", ctx.hidden_text_by_page.get(page_no, "")))
        if total < 200 or hidden < 40:
            continue
        share = hidden / total
        if share < 0.12:
            continue
        out.append(
            Finding(
                code="layer_mismatch",
                detector="Text layer mismatch",
                severity="high" if share > 0.3 else "medium",
                title=f"{share:.0%} of this page's text is not visible on it",
                detail=(
                    "Most of a normal document is meant to be read. A large hidden "
                    "fraction means the file is carrying a second message for whatever "
                    "parses it."
                ),
                technique="Aggregate divergence",
                evidence=f"{hidden} hidden characters of {total} extractable",
                page=page_no,
                extra={"hidden_chars": hidden, "total_chars": total, "share": round(share, 4)},
            )
        )
    return out


def detect_encoding_anomalies(ctx) -> list[Finding]:
    """Control characters and unusual category mixes in the text layer."""
    out: list[Finding] = []
    for source in ctx.text_sources():
        text, page_no, where = source["text"], source["page"], source["source"]
        controls = collections.Counter(
            ch for ch in text if unicodedata.category(ch) == "Cc" and ch not in "\n\r\t"
        )
        private = sum(
            1
            for ch in text
            if any(lo <= ord(ch) <= hi for lo, hi in patterns.PRIVATE_USE_RANGES)
        )
        if not controls and private < 3:
            continue
        bits = []
        if controls:
            bits.append(f"{sum(controls.values())} control characters")
        if private >= 3:
            bits.append(f"{private} private-use code points")
        out.append(
            Finding(
                code="encoding_anomaly",
                detector="Encoding anomaly",
                severity="medium",
                title=f"Unusual code points in {where}",
                detail=(
                    "Control and private-use characters do not occur in text that was "
                    "typed by a person. They are usually either filter evasion or the "
                    "residue of a generated payload."
                ),
                technique="Non-printing code points",
                evidence=" and ".join(bits),
                page=page_no,
                extra={"where": where, "controls": sum(controls.values()), "private_use": private},
            )
        )
    return out


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

ALL_DETECTORS = [
    ("invisible_render_mode", detect_invisible_render_mode),
    ("transparent_text", detect_transparent_text),
    ("low_contrast_text", detect_low_contrast_text),
    ("micro_type", detect_micro_type),
    ("offpage_text", detect_offpage_text),
    ("covered_text", detect_covered_text),
    ("hidden_layer", detect_hidden_layers),
    ("metadata_payload", detect_metadata_payload),
    ("annotation_payload", detect_annotation_payload),
    ("form_field_payload", detect_form_field_payload),
    ("embedded_file", detect_embedded_files),
    ("active_content", detect_active_content),
    ("invisible_unicode", detect_invisible_unicode),
    ("homoglyph", detect_homoglyphs),
    ("injection_language", detect_injection_language),
    ("layer_mismatch", detect_text_layer_mismatch),
    ("encoding_anomaly", detect_encoding_anomalies),
]

DETECTOR_INFO = {
    "invisible_render_mode": "Text painted in render mode 3, which puts no ink on the page.",
    "transparent_text": "Glyphs drawn at an alpha low enough to be invisible.",
    "low_contrast_text": "Fill colour measured against the real background beneath it.",
    "micro_type": "Type set below the threshold where glyphs resolve.",
    "offpage_text": "Glyphs positioned outside the crop box.",
    "covered_text": "Text drawn first, then buried under an opaque shape.",
    "hidden_layer": "Optional content groups that viewers hide by default.",
    "metadata_payload": "Instruction text in document metadata or XMP.",
    "annotation_payload": "Annotation contents, including hidden-flagged ones.",
    "form_field_payload": "AcroForm values and tooltips that parsers read.",
    "embedded_file": "Attachments riding inside the document.",
    "active_content": "JavaScript, open actions and automatic triggers.",
    "invisible_unicode": "Zero-width, bidi and Unicode Tag smuggling.",
    "homoglyph": "Cyrillic and Greek letters standing in for Latin ones.",
    "injection_language": "Phrasing addressed to a model rather than a reader.",
    "layer_mismatch": "Ratio of hidden to visible text across a page.",
    "encoding_anomaly": "Control and private-use code points in the text layer.",
}
