"""
docscan.py - checks an uploaded loan PDF for hidden instructions BEFORE any AI reads it.

Plain code, no AI. A document is QUARANTINED if anything is found, and then the AI never
sees it (policy A). Checks:
  * hidden text: white text (assumes a white page), tiny text, text off the page,
    text drawn in invisible mode
  * invisible Unicode characters (zero-width, direction overrides, tag characters)
  * instructions in metadata, comments/annotations, and active content (JavaScript,
    launch actions, embedded files)
  * instruction-like phrases anywhere, including the visible text
The PDF is read in memory only; nothing is written to disk.
"""
import hashlib
import io
import logging
import math
import re
from dataclasses import dataclass, field

from pypdf import PdfReader

logging.getLogger("pypdf").setLevel(logging.ERROR)   # malformed files are handled below

MAX_BYTES = 2 * 1024 * 1024
MAX_PAGES = 5
MAX_TEXT = 20000
TINY_PT = 3.0           # text smaller than this is not meant to be read by a person
WHITE = 0.95            # fill colour at least this light counts as white (on a white page)
SNIPPET = 200

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
_PATTERNS = [
    r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules|prompts?|guidelines|polic(y|ies))\b",
    r"\byou are now\b",
    r"\b(system|assistant)\s*:",
    r"\bnote to (the )?(ai|assistant|model|llm|reviewer|bot)\b",
    r"\b(ai|llm|chatbot|language model|assistant|reviewer)\b.{0,30}\b(approve|mark|classify|rate|ignore|do not)\b",
    r"\b(mark|classify|rate|treat|score)\b.{0,40}\blow[- ]risk\b",
    r"\bdo not (flag|report|mention|reveal|escalate)\b",
]
_PHRASES = [re.compile(p, re.I | re.S) for p in _PATTERNS]
_META_KEYS = ("/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer")


class DocRejected(ValueError):
    """Not a document we accept at all (wrong type, too big, encrypted, unreadable)."""


@dataclass
class ScanResult:
    verdict: str                      # CLEAN | QUARANTINED
    sha256: str
    pages: int
    visible_text: str
    findings: list[dict] = field(default_factory=list)

    @property
    def kinds(self) -> list[str]:
        return sorted({f["kind"] for f in self.findings})


def _plain(text: str) -> str:
    return " ".join(_INVISIBLE.sub("", text or "").split())


def phrase_hits(text: str) -> list[str]:
    clean = _plain(text)
    return [m.group(0) for p in _PHRASES for m in [p.search(clean)] if m]


def _add(findings, kind, where, text, detail=""):
    findings.append({"kind": kind, "where": where, "detail": detail,
                     "text": _plain(text)[:SNIPPET]})


def _scale(m) -> float:
    return math.hypot(m[2], m[3]) or math.hypot(m[0], m[1]) or 1.0


def _is_white(color) -> bool:
    if not color:
        return False
    if len(color) == 4:                          # CMYK: white = no ink
        return all(c <= 1 - WHITE for c in color)
    return all(c >= WHITE for c in color)        # gray or RGB


def _page_text(page, page_no, findings) -> str:
    """Visible text of one page; hidden pieces become findings."""
    box = page.mediabox
    left, bottom, right, top = float(box.left), float(box.bottom), float(box.right), float(box.top)
    state = {"fill": None, "mode": 0}
    stack: list[dict] = []
    visible: list[str] = []
    hidden: dict[str, list[str]] = {}

    def before(op, args, cm, tm):
        if op == b"q":
            stack.append(dict(state))
        elif op == b"Q" and stack:
            state.update(stack.pop())
        elif op in (b"g", b"rg", b"k", b"sc", b"scn"):
            try:
                state["fill"] = [float(a) for a in args if isinstance(a, (int, float))] or None
            except (TypeError, ValueError):
                state["fill"] = None
        elif op == b"Tr" and args:
            state["mode"] = int(args[0])

    def on_text(text, cm, tm, font, size):
        if not text:
            return
        if not text.strip():
            visible.append(text)
            return
        x = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
        y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
        eff = abs(float(size or 0)) * _scale(tm) * _scale(cm)
        if state["mode"] in (3, 7):
            reason = "hidden_invisible_mode"
        elif _is_white(state["fill"]):
            reason = "hidden_white_text"
        elif 0 < eff < TINY_PT:
            reason = "hidden_tiny_text"
        elif not (left - 5 <= x <= right and bottom - 5 <= y <= top):
            reason = "hidden_offpage_text"
        else:
            visible.append(text)
            return
        hidden.setdefault(reason, []).append(text)

    page.extract_text(visitor_operand_before=before, visitor_text=on_text)
    details = {"hidden_invisible_mode": "drawn in invisible mode",
               "hidden_white_text": "white text on a white page",
               "hidden_tiny_text": f"text smaller than {TINY_PT:g} pt",
               "hidden_offpage_text": "text placed outside the page"}
    for kind, parts in hidden.items():
        _add(findings, kind, f"page {page_no}", " ".join(parts), details[kind])

    for annot in page.get("/Annots") or []:
        try:
            a = annot.get_object()
        except Exception:  # noqa: BLE001
            continue
        if a.get("/Subtype") == "/Link":
            continue
        text = " ".join(str(a.get(k, "")) for k in ("/Contents", "/T", "/RC") if a.get(k))
        if text.strip():
            _add(findings, "annotation_text", f"page {page_no}", text, "comment / annotation text")
    return "".join(visible)


def _active_content(reader, findings):
    root = reader.trailer["/Root"]
    names = root.get("/Names")
    names = names.get_object() if names is not None else {}
    checks = [
        ("/JavaScript" in names, "JavaScript"),
        ("/EmbeddedFiles" in names, "embedded files"),
        ("/OpenAction" in root, "action when opened"),
        ("/AA" in root, "automatic actions"),
    ]
    acro = root.get("/AcroForm")
    if acro is not None and "/XFA" in acro.get_object():
        checks.append((True, "XFA form"))
    for hit, what in checks:
        if hit:
            _add(findings, "active_content", "document", what, "active content is not accepted")


def scan(data: bytes) -> ScanResult:
    if len(data) > MAX_BYTES:
        raise DocRejected(f"file is larger than {MAX_BYTES // (1024 * 1024)} MB")
    if not data.startswith(b"%PDF-"):
        raise DocRejected("only PDF files are accepted")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise DocRejected("encrypted PDFs are not accepted")
        pages = len(reader.pages)
    except DocRejected:
        raise
    except Exception:  # noqa: BLE001
        raise DocRejected("could not read this PDF") from None
    if pages > MAX_PAGES:
        raise DocRejected(f"more than {MAX_PAGES} pages")

    findings: list[dict] = []
    try:
        visible = "\n".join(_page_text(p, i, findings) for i, p in enumerate(reader.pages, start=1))
        _active_content(reader, findings)
        meta = reader.metadata or {}
    except Exception:  # noqa: BLE001
        raise DocRejected("could not read this PDF") from None
    visible = visible[:MAX_TEXT]

    if _INVISIBLE.search(visible):
        _add(findings, "invisible_characters", "visible text", visible, "zero-width or direction characters")
    for key in _META_KEYS:
        value = str(meta.get(key) or "")
        if not value:
            continue
        if _INVISIBLE.search(value) or phrase_hits(value) or len(value) > 200:
            _add(findings, "metadata_instructions", f"metadata {key[1:]}", value,
                 "invisible characters" if _INVISIBLE.search(value) else "instruction-like metadata")

    for f in list(findings):
        if f["kind"] != "instruction_phrases":
            hits = phrase_hits(f["text"])
            if hits:
                f["detail"] += f"; contains: \"{hits[0][:60]}\""
    hits = phrase_hits(visible)
    if hits:
        _add(findings, "instruction_phrases", "visible text", hits[0], "instruction aimed at an AI")

    return ScanResult("QUARANTINED" if findings else "CLEAN", hashlib.sha256(data).hexdigest(),
                      pages, visible, findings)


def _norm(text: str) -> str:
    text = _plain(text).lower().replace("₹", "rs").replace("inr", "rs")
    return re.sub(r"[^a-z0-9.]", "", text)


def verify_fields(fields: dict, labels: dict, visible_text: str) -> list[dict]:
    """Each AI-filled value counts as verified only if it really appears in the VISIBLE text."""
    haystack = _norm(visible_text)
    out = []
    for name, label in labels.items():
        value = _plain(str(fields.get(name) or ""))[:60]
        needle = _norm(value)
        ok = bool(needle) and len(needle) >= 2 and needle in haystack
        # An unverified value is never shown: it could be invented or injected.
        out.append({"name": name, "label": label, "value": value if ok else "", "verified": ok})
    return out
