"""Lexicons used to recognise text that is addressed to a language model
rather than to a human reader.

Everything here is data only: no I/O, no side effects. Keeping the
patterns in one module means the detectors stay readable and the lexicon
can be tuned without touching scanning logic.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# Prompt-injection phrasing
# --------------------------------------------------------------------------
# Each entry is (compiled pattern, weight, human-readable label).
# Weight is a rough confidence that the phrase is addressed to a model.

_RAW_PHRASES: list[tuple[str, int, str]] = [
    # Direct instruction overrides
    (r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding|foregoing)\s+"
     r"(instruction|instructions|prompt|prompts|direction|directions|rule|rules|context)",
     10, "Instruction override"),
    (r"disregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+"
     r"(instruction|instructions|prompt|prompts|rule|rules|content)",
     10, "Instruction override"),
    (r"forget\s+(everything|all)\s+(you\s+)?(were\s+told|above|before|previously)",
     10, "Instruction override"),
    (r"override\s+(your\s+|the\s+)?(system\s+)?(prompt|instructions|rules|guidelines)",
     10, "Instruction override"),
    (r"(new|updated|revised)\s+(system\s+)?(instruction|instructions|prompt|directive)s?\s*[:\-]",
     9, "Instruction override"),
    (r"end\s+of\s+(document|resume|r\u00e9sum\u00e9|cv|context)\s*[.\-]*\s*(new|system|begin)",
     9, "Context boundary spoofing"),

    # Role / persona hijack
    (r"you\s+are\s+(now\s+)?(an?\s+)?(helpful\s+)?(ai|assistant|language\s+model|recruiter|screener|evaluator)",
     8, "Role hijack"),
    (r"as\s+an?\s+(ai|language\s+model|automated\s+(screener|reviewer|system))",
     6, "Model addressed directly"),
    (r"\bsystem\s*[:>]\s*",
     7, "Fake system turn"),
    (r"<\s*/?\s*(system|assistant|user|im_start|im_end|instructions?)\s*>",
     9, "Chat-markup injection"),
    (r"\[\s*(system|assistant|instruction|internal)\s*\]",
     8, "Chat-markup injection"),
    (r"###\s*(system|instruction|important)\b",
     7, "Chat-markup injection"),

    # Scoring / ranking manipulation
    (r"(rank|rate|score|grade)\s+(this\s+)?(candidate|applicant|resume|r\u00e9sum\u00e9|cv|application|paper|submission)?\s*"
     r"(as\s+)?(the\s+)?(first|top|highest|1st|100|10/10|a\s+strong\s+(match|fit))",
     10, "Score manipulation"),
    (r"(recommend|advance|forward|move)\s+(this\s+)?(candidate|applicant|submission)\s+"
     r"(to\s+)?(the\s+)?(next\s+round|interview|hiring\s+manager|immediately)",
     9, "Score manipulation"),
    (r"(strong|perfect|exceptional|ideal|excellent)\s+(match|fit|candidate)\s+for\s+(this|the)\s+(role|position|job)",
     5, "Score manipulation"),
    (r"do\s+not\s+(reject|filter|screen\s+out|disqualify|flag)",
     9, "Score manipulation"),
    (r"(skip|bypass|omit)\s+(further\s+|any\s+|all\s+)?(review|screening|verification|checks?)",
     9, "Review suppression"),
    (r"accept\s+(this\s+)?(paper|submission|candidate|application)\b",
     7, "Score manipulation"),
    (r"give\s+(a\s+)?(positive|favou?rable|glowing)\s+(review|assessment|recommendation)",
     8, "Score manipulation"),

    # Exfiltration / tool abuse
    (r"(send|email|post|forward|transmit)\s+(the\s+|your\s+|all\s+)?"
     r"(system\s+prompt|instructions|context|conversation|contents|data)\s+to\b",
     10, "Data exfiltration"),
    (r"(visit|fetch|browse|open|curl|request)\s+(the\s+)?(url|link|https?://|site)",
     6, "Outbound fetch request"),
    (r"base64|atob\(|fromCharCode",
     4, "Encoded payload marker"),

    # Secrecy
    (r"do\s+not\s+(mention|reveal|disclose|show|tell|output|repeat)\s+(this|these|the\s+above)",
     9, "Concealment instruction"),
    (r"(this|the\s+following)\s+(text|instruction|message)\s+is\s+(only\s+)?for\s+(the\s+)?"
     r"(ai|model|assistant|parser|system)",
     10, "Model addressed directly"),
    (r"human(s)?\s+(will\s+not|cannot|can't|won't)\s+(see|read)\s+this",
     10, "Concealment instruction"),
    (r"invisible\s+to\s+(the\s+)?(human|reader|recruiter)",
     9, "Concealment instruction"),
]

INJECTION_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(pat, re.IGNORECASE), weight, label)
    for pat, weight, label in _RAW_PHRASES
]

# A phrase score at or above this is treated as a confirmed injection.
INJECTION_CONFIRM_SCORE = 9
INJECTION_SUSPECT_SCORE = 5


# --------------------------------------------------------------------------
# Invisible / control characters
# --------------------------------------------------------------------------
# Characters that carry no visible mark but survive text extraction, so a
# model reads them while a person never sees them.

INVISIBLE_CHARS: dict[str, str] = {
    "\u200b": "Zero-width space",
    "\u200c": "Zero-width non-joiner",
    "\u200d": "Zero-width joiner",
    "\u2060": "Word joiner",
    "\ufeff": "Zero-width no-break space (BOM)",
    "\u00ad": "Soft hyphen",
    "\u180e": "Mongolian vowel separator",
    "\u2061": "Function application",
    "\u2062": "Invisible times",
    "\u2063": "Invisible separator",
    "\u2064": "Invisible plus",
}

# Bidirectional overrides can visually reorder text so the rendered string
# differs from the extracted string ("Trojan Source").
BIDI_CHARS: dict[str, str] = {
    "\u202a": "Left-to-right embedding",
    "\u202b": "Right-to-left embedding",
    "\u202c": "Pop directional formatting",
    "\u202d": "Left-to-right override",
    "\u202e": "Right-to-left override",
    "\u2066": "Left-to-right isolate",
    "\u2067": "Right-to-left isolate",
    "\u2068": "First-strong isolate",
    "\u2069": "Pop directional isolate",
}

# Unicode Tag characters (U+E0000-U+E007F) render as nothing at all but map
# 1:1 onto ASCII. They are the cleanest way to hide a full sentence in a
# string that looks like a single emoji or word.
TAG_RANGE = (0xE0000, 0xE007F)

# Private use areas are sometimes used to smuggle payloads past filters.
PRIVATE_USE_RANGES = [(0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD)]


def decode_tag_chars(text: str) -> str:
    """Turn a run of Unicode Tag characters back into the ASCII it encodes."""
    out = []
    for ch in text:
        cp = ord(ch)
        if TAG_RANGE[0] <= cp <= TAG_RANGE[1]:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


# --------------------------------------------------------------------------
# Confusable / homoglyph characters
# --------------------------------------------------------------------------
# Latin look-alikes drawn from Cyrillic and Greek. Used to spot spoofed
# domains and company names inside a document.

HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u04bb": "h",
    "\u0455": "s", "\u0405": "S", "\u0410": "A", "\u0412": "B", "\u0415": "E",
    "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0391": "A", "\u0392": "B",
    "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a7": "X", "\u03bf": "o", "\u03b1": "a", "\u03b2": "b", "\u03b9": "i",
    "\u0131": "i", "\u2044": "/", "\u2215": "/",
}

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'\)]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def find_injection_hits(text: str) -> list[dict]:
    """Return every injection phrase found in ``text``.

    Overlapping matches from different patterns are kept, because two
    different manipulation techniques in the same sentence is a stronger
    signal than one.
    """
    hits: list[dict] = []
    seen: set[tuple[int, int, str]] = set()
    for pattern, weight, label in INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            key = (match.start(), match.end(), label)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "label": label,
                    "weight": weight,
                    "start": match.start(),
                    "end": match.end(),
                    "match": match.group(0).strip(),
                }
            )
    hits.sort(key=lambda h: (-h["weight"], h["start"]))
    return hits
