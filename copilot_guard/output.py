"""Checking the model's reply before an analyst sees it. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .normalize import detect_injection  # noqa: F401  (used by triage)

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
NEXT_STEPS = {"escalate_to_analyst", "request_more_context", "monitor", "open_incident"}
ALLOWED_LINK_HOSTS = {"attack.mitre.org", "hisn.local"}


class Rejected(Exception):
    """Raised by parse_model_output / triage when the reply cannot be accepted. Keeps .reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class TriageResult:
    severity: str
    summary_html: str
    next_step: str
    related_alert_ids: list[str]
    flags: list[str] = field(default_factory=list)


FORBIDDEN_KEYS = ("action", "actions", "tool_call", "tool_calls", "function_call")
_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
# Either a markdown link [text](url ...) or a bare http(s) URL. A link is matched whole, so a
# bare-URL match can never fire on the URL of a link we decided to keep.
_LINK_OR_URL_RE = re.compile(
    r"\[(?P<text>[^\]]*)\]\(\s*(?P<url>[^)\s]*)[^)]*\)|(?P<bare>https?://[^\s<>\"']+)",
    re.IGNORECASE,
)
_BARE_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TENANT_RE = re.compile(r"TEN-[0-9]{3}")


def _allowed_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return parts.scheme.lower() in ("http", "https") and parts.hostname in ALLOWED_LINK_HOSTS
    except ValueError:
        return False


def _strip_bare_urls(text: str, flags: set[str]) -> str:
    def repl(m: re.Match) -> str:
        url = m.group(0)
        trail = ""
        while url and url[-1] in ".,;:!?)]}":
            trail = url[-1] + trail
            url = url[:-1]
        if _allowed_url(url):
            return m.group(0)
        flags.add("link_removed")
        return "[link removed]" + trail

    return _BARE_URL_RE.sub(repl, text)


def _clean_summary(summary: str, flags: set[str]) -> str:
    if _IMAGE_RE.search(summary):
        flags.add("image_removed")
        summary = _IMAGE_RE.sub("[image removed]", summary)

    def repl(m: re.Match) -> str:
        if m.group("bare") is not None:
            return _strip_bare_urls(m.group("bare"), flags)
        text = _strip_bare_urls(m.group("text"), flags)
        if _allowed_url(m.group("url")):
            if text == m.group("text"):
                return m.group(0)
            return f"[{text}]({m.group('url')})"
        flags.add("link_removed")
        return text

    return html.escape(_LINK_OR_URL_RE.sub(repl, summary), quote=True)


def _reject(reason: str):
    raise Rejected(reason)


def parse_model_output(raw: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Parse, validate and clean one model reply. See README.md for the exact seven-step order."""
    # 1. strip, unwrap one fenced block, parse a JSON object
    text = raw.strip() if isinstance(raw, str) else ""
    lines = text.split("\n")
    if len(lines) >= 2 and lines[0].strip() in ("```json", "```") and lines[-1].strip() == "```":
        text = "\n".join(lines[1:-1]).strip()
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        _reject("not_json")
    if not isinstance(obj, dict):
        _reject("not_json")

    # 2. forbidden actions
    if any(k in obj for k in FORBIDDEN_KEYS):
        _reject("forbidden_action")
    step = obj.get("next_step")
    if isinstance(step, str) and "close" in step.lower():
        _reject("forbidden_action")

    # 3. field rules
    severity = obj.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITIES:
        _reject("bad_severity")
    if not isinstance(step, str) or step not in NEXT_STEPS:
        _reject("bad_next_step")
    summary = obj.get("summary")
    if not isinstance(summary, str):
        _reject("bad_summary")
    summary = summary.strip()
    if not summary or len(summary) > 600:
        _reject("bad_summary")
    related = obj.get("related_alert_ids", [])
    if not isinstance(related, list) or not all(isinstance(x, str) for x in related):
        _reject("bad_related_alert_ids")

    # 4. other tenants
    if any(t != tenant_id for t in _TENANT_RE.findall(summary)):
        _reject("cross_tenant_reference")

    flags: set[str] = set()

    # 5. related ids
    ids: list[str] = []
    for x in related:
        if x not in ids:
            ids.append(x)
    kept = [x for x in ids if x in known_alert_ids]
    if len(kept) != len(ids):
        flags.add("unknown_alert_id")

    # 6. summary clean-up and escaping
    clean = _clean_summary(summary, flags)

    return TriageResult(severity=severity, summary_html=clean, next_step=step,
                        related_alert_ids=kept, flags=sorted(flags))


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _strings(v)


def triage(alert: dict, raw_output: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Run detect_injection over every string in `alert`, then parse_model_output; if any signal
    fired, add flags and never let the result end up quieter than it would otherwise be."""
    result = parse_model_output(raw_output, tenant_id=tenant_id, known_alert_ids=known_alert_ids)
    signals: set[str] = set()
    for s in _strings(alert):
        signals.update(detect_injection(s))
    if signals:
        flags = set(result.flags) | {"possible_injection"} | {f"signal:{c}" for c in signals}
        result.flags = sorted(flags)
        if SEVERITIES.index(result.severity) < SEVERITIES.index("high"):
            result.severity = "high"
        if result.next_step == "monitor":
            result.next_step = "escalate_to_analyst"
    return result
