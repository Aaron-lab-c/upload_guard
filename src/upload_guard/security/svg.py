"""SVG scanning and sanitising (XSS, external references, XXE).

The scanner is a whitelist-leaning filter built on the standard-library XML
parser:

* ``<script>``, ``<foreignObject>``, HTML-ish elements and elements in unknown
  namespaces are removed.
* ``on*`` event-handler attributes are removed.
* URL-bearing attributes (``href``, ``xlink:href``, ``src``, ...) must be a
  fragment, a relative path, ``http(s)``/``mailto`` (links only) or a raster
  ``data:image/...`` URI. ``javascript:``, ``data:text/html`` and friends are
  removed.
* CSS (``style`` attribute / ``<style>``) may not use ``expression()``,
  ``javascript:``, ``-moz-binding``, ``behavior:``, ``@import`` or external
  ``url()``.
* ``<!DOCTYPE>`` internal subsets / ``<!ENTITY>`` declarations are rejected
  before parsing (billion-laughs / XXE), so the XML parser never sees them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple
from xml.etree import ElementTree as ET

from ..types import Finding, Severity

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
XML_NS = "http://www.w3.org/XML/1998/namespace"
XHTML_NS = "http://www.w3.org/1999/xhtml"

_KNOWN_NAMESPACES: Dict[str, str] = {
    "": SVG_NS,
    "xlink": XLINK_NS,
    "inkscape": "http://www.inkscape.org/namespaces/inkscape",
    "sodipodi": "http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "cc": "http://creativecommons.org/ns#",
    "dc": "http://purl.org/dc/elements/1.1/",
    "xml": XML_NS,
}
for _prefix, _uri in _KNOWN_NAMESPACES.items():
    if _prefix != "xml":
        ET.register_namespace(_prefix, _uri)

ALLOWED_NAMESPACES: FrozenSet[str] = frozenset(_KNOWN_NAMESPACES.values())

#: Elements that execute code or embed foreign content.
SCRIPT_ELEMENTS: FrozenSet[str] = frozenset({"script"})
FOREIGN_ELEMENTS: FrozenSet[str] = frozenset({"foreignobject"})
DANGEROUS_ELEMENTS: FrozenSet[str] = frozenset({
    "iframe", "embed", "object", "applet", "frame", "frameset", "html", "body", "head", "meta", "base",
    "link", "form", "input", "button", "textarea", "select", "option", "audio", "video", "source", "track",
    "handler", "listener", "annotation-xml", "math", "canvas", "template", "slot", "portal", "noscript",
    "prefetch", "discard",
})
ANIMATION_ELEMENTS: FrozenSet[str] = frozenset({"animate", "animatetransform", "animatemotion", "animatecolor", "set"})
HREF_ATTRIBUTES: FrozenSet[str] = frozenset({"href", "xlink:href"})
#: HTML attributes that have no business in SVG and always fetch/execute something.
ALWAYS_REMOVE_ATTRIBUTES: FrozenSet[str] = frozenset({
    "src", "data", "action", "formaction", "poster", "codebase", "background", "dynsrc", "lowsrc", "srcset",
    "ping", "manifest", "profile", "archive", "code", "classid", "usemap", "longdesc", "contenteditable",
})
LINK_ELEMENTS: FrozenSet[str] = frozenset({"a"})
IMAGE_ELEMENTS: FrozenSet[str] = frozenset({"image", "feimage"})
#: Attributes whose value is a CSS ``url(...)`` reference to another element.
PAINT_ATTRIBUTES: FrozenSet[str] = frozenset({"fill", "stroke", "filter", "clip-path", "mask", "marker-start", "marker-mid", "marker-end", "marker", "cursor"})
#: Attributes on animation elements that carry the target value.
ANIMATION_VALUE_ATTRIBUTES: FrozenSet[str] = frozenset({"to", "from", "values", "by"})

SCRIPT_SCHEMES: FrozenSet[str] = frozenset({"javascript", "vbscript", "livescript", "mocha", "jscript", "ecmascript", "data-javascript"})
SAFE_LINK_SCHEMES: FrozenSet[str] = frozenset({"http", "https", "mailto", "tel", "ftp", "ftps", "sms", "xmpp", "irc", "news", "nntp"})
SAFE_DATA_IMAGE_TYPES: FrozenSet[str] = frozenset({"image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp", "image/bmp", "image/x-icon", "image/vnd.microsoft.icon", "image/avif", "image/heic", "image/tiff"})

_STRIP_RE = re.compile("[\x00-\x20\x7f-\x9f​-‏  ‪-‮﻿]")
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]*):")
_DATA_RE = re.compile(r"^data:([a-z0-9!#$&^_.+\-]+/[a-z0-9!#$&^_.+\-]+)?", re.IGNORECASE)
_ENTITY_RE = re.compile(rb"<!ENTITY", re.IGNORECASE)
_DOCTYPE_RE = re.compile(rb"<!DOCTYPE[^>\[]*(\[[\s\S]*?\]\s*)?>", re.IGNORECASE)
_PI_RE = re.compile(rb"<\?(?!xml[\s?])[\s\S]*?\?>", re.IGNORECASE)
_CSS_DANGEROUS_RE = re.compile(r"expression\s*\(|javascript\s*:|vbscript\s*:|-moz-binding|behaviou?r\s*:|-o-link|@import|data\s*:\s*text", re.IGNORECASE)
_CSS_URL_RE = re.compile(r"url\(\s*(['\"]?)([^'\")]*)\1\s*\)", re.IGNORECASE)
_CSS_IMPORT_RE = re.compile(r"@import[^;]*;?", re.IGNORECASE)
_CSS_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")


@dataclass(frozen=True)
class SvgPolicy:
    """Tunable knobs for :func:`scan_svg` / :func:`sanitize_svg`."""

    allow_external_references: bool = False  # http(s) <image>/<use> targets
    allow_data_images: bool = True  # data:image/png;base64,... in <image>
    allow_style: bool = True  # keep style attributes / <style> (filtered)
    allow_animation: bool = True  # keep <animate>/<set> (filtered)
    allow_links: bool = True  # keep <a href="https://...">
    blocked_elements: FrozenSet[str] = frozenset()
    blocked_attributes: FrozenSet[str] = frozenset()
    max_bytes: int = 10 * 1024 * 1024
    max_elements: int = 100_000
    max_depth: int = 512


DEFAULT_POLICY = SvgPolicy()


@dataclass
class SvgResult:
    findings: List[Finding] = field(default_factory=list)
    sanitized: Optional[bytes] = None
    element_count: int = 0

    @property
    def is_clean(self) -> bool:
        return not any(f.severity >= Severity.MEDIUM and not f.remediated for f in self.findings)


def _local(tag: str) -> Tuple[str, str]:
    """Split ``{ns}local`` into ``(ns, local.lower())``."""
    if tag.startswith("{"):
        ns, _, local = tag[1:].partition("}")
        return ns, local.lower()
    return "", tag.lower()


def _attr_name(name: str) -> str:
    ns, local = _local(name)
    if ns == XLINK_NS:
        return "xlink:" + local
    if ns == XML_NS:
        return "xml:" + local
    return local


def classify_url(value: str) -> str:
    """Classify a URL as one of fragment / relative / safe_scheme / data_image /
    data_other / script / external / unknown_scheme / empty."""
    v = _STRIP_RE.sub("", value or "").lower()
    if not v:
        return "empty"
    if v.startswith("#"):
        return "fragment"
    m = _SCHEME_RE.match(v)
    if not m:
        if v.startswith("//"):
            return "external"
        return "relative"
    scheme = m.group(1)
    if scheme in SCRIPT_SCHEMES:
        return "script"
    if scheme == "data":
        dm = _DATA_RE.match(v)
        media = (dm.group(1) or "text/plain").lower() if dm else "text/plain"
        return "data_image" if media in SAFE_DATA_IMAGE_TYPES else "data_other"
    if scheme in SAFE_LINK_SCHEMES:
        return "external"
    return "unknown_scheme"


class _Sanitizer:
    def __init__(self, policy: SvgPolicy, modify: bool) -> None:
        self.policy = policy
        self.modify = modify
        self.findings: List[Finding] = []
        self.element_count = 0

    # -- helpers ------------------------------------------------------------
    def add(self, code: str, severity: Severity, message: str, **detail: object) -> None:
        self.findings.append(Finding(code, severity, message, dict(detail), remediated=self.modify))

    @staticmethod
    def _remove_child(parent: ET.Element, child: ET.Element, prev: Optional[ET.Element]) -> None:
        tail = child.tail or ""
        if tail:
            if prev is not None:
                prev.tail = (prev.tail or "") + tail
            else:
                parent.text = (parent.text or "") + tail
        parent.remove(child)

    # -- element decision -----------------------------------------------------
    def element_verdict(self, el: ET.Element) -> Optional[Tuple[str, Severity, str]]:
        """Return (code, severity, message) when the element must go, else None."""
        ns, local = _local(el.tag)
        if ns and ns not in ALLOWED_NAMESPACES:
            sev = Severity.HIGH if ns == XHTML_NS else Severity.MEDIUM
            return "svg.foreign_element", sev, "Element <%s> from foreign namespace %s" % (local, ns)
        if local in SCRIPT_ELEMENTS:
            return "svg.script", Severity.CRITICAL, "<script> element"
        if local in FOREIGN_ELEMENTS:
            return "svg.foreign_object", Severity.HIGH, "<foreignObject> element (embeds HTML)"
        if local in DANGEROUS_ELEMENTS or local in self.policy.blocked_elements:
            return "svg.dangerous_element", Severity.HIGH, "<%s> element is not allowed in SVG" % local
        if local in ANIMATION_ELEMENTS:
            if not self.policy.allow_animation:
                return "svg.animation", Severity.LOW, "Animation element <%s> removed by policy" % local
            target = (el.get("attributeName") or "").strip().lower()
            if target in HREF_ATTRIBUTES or target.endswith(":href") or target in ("style", "onload"):
                return "svg.animated_href", Severity.HIGH, "<%s> animates %r (can inject a URL)" % (local, target)
            for a in ANIMATION_VALUE_ATTRIBUTES:
                val = el.get(a)
                if val is not None:
                    for part in val.split(";"):
                        if classify_url(part) in ("script", "data_other"):
                            return "svg.javascript_uri", Severity.CRITICAL, "Script URI in <%s %s>" % (local, a)
        if local == "style":
            if not self.policy.allow_style:
                return "svg.style", Severity.LOW, "<style> removed by policy"
            text = "".join(el.itertext())
            if _CSS_DANGEROUS_RE.search(_CSS_COMMENT_RE.sub("", text)):
                return "svg.css_script", Severity.CRITICAL, "<style> contains script-capable CSS (expression/javascript/binding/@import)"
        if local == "a" and not self.policy.allow_links:
            return "svg.link", Severity.LOW, "<a> removed by policy"
        return None

    # -- attributes -------------------------------------------------------------
    def process_attributes(self, el: ET.Element) -> None:
        _, local = _local(el.tag)
        for raw_name in list(el.attrib.keys()):
            name = _attr_name(raw_name)
            value = el.attrib[raw_name]
            verdict = self.attribute_verdict(local, name, value, el)
            if verdict is None:
                continue
            code, severity, message, replacement = verdict
            self.add(code, severity, message, element=local, attribute=name)
            if self.modify:
                if replacement is None:
                    del el.attrib[raw_name]
                else:
                    el.attrib[raw_name] = replacement

    def attribute_verdict(self, element: str, name: str, value: str, el: ET.Element) -> Optional[Tuple[str, Severity, str, Optional[str]]]:
        if name.startswith("on") and len(name) > 2:
            return "svg.event_handler", Severity.CRITICAL, "Event handler attribute %s" % name, None
        if name in ALWAYS_REMOVE_ATTRIBUTES or name in self.policy.blocked_attributes:
            return "svg.dangerous_attribute", Severity.HIGH, "Attribute %s is not allowed" % name, None
        if name in HREF_ATTRIBUTES:
            kind = classify_url(value)
            if kind == "script":
                return "svg.javascript_uri", Severity.CRITICAL, "Script URI in %s" % name, None
            if kind == "data_other":
                return "svg.data_uri", Severity.HIGH, "Non-image data: URI in %s" % name, None
            if kind == "unknown_scheme":
                return "svg.unknown_scheme", Severity.MEDIUM, "Unknown URL scheme in %s" % name, None
            if element in LINK_ELEMENTS:
                return None  # links to http(s)/mailto/relative/# are fine
            if kind == "data_image":
                if element in IMAGE_ELEMENTS and self.policy.allow_data_images:
                    return None
                return "svg.data_uri", Severity.MEDIUM, "data: URI in <%s %s>" % (element, name), None
            if kind in ("external", "relative"):
                if self.policy.allow_external_references:
                    return None
                sev = Severity.HIGH if element == "use" else Severity.MEDIUM
                return "svg.external_reference", sev, "External reference in <%s %s>" % (element, name), None
            return None  # fragment / empty
        if name == "style":
            if not self.policy.allow_style:
                return "svg.style", Severity.LOW, "style attribute removed by policy", None
            return self.css_verdict(value, "style attribute")
        if name in PAINT_ATTRIBUTES:
            m = _CSS_URL_RE.search(value)
            if m and classify_url(m.group(2)) != "fragment":
                kind = classify_url(m.group(2))
                sev = Severity.CRITICAL if kind == "script" else Severity.MEDIUM
                return "svg.external_reference", sev, "Non-local url() in %s" % name, None
        if element in ANIMATION_ELEMENTS and name in ANIMATION_VALUE_ATTRIBUTES:
            return None  # handled at element level
        if name == "target" and value.strip().lower() not in ("", "_self", "_blank", "_parent", "_top"):
            return "svg.dangerous_attribute", Severity.LOW, "Unusual target value", "_blank"
        return None

    def css_verdict(self, css: str, where: str) -> Optional[Tuple[str, Severity, str, Optional[str]]]:
        stripped = _CSS_COMMENT_RE.sub("", css)
        if _CSS_DANGEROUS_RE.search(stripped):
            return "svg.css_script", Severity.CRITICAL, "Script-capable CSS in %s" % where, None
        bad = False
        for m in _CSS_URL_RE.finditer(stripped):
            kind = classify_url(m.group(2))
            if kind == "fragment" or (kind == "data_image" and self.policy.allow_data_images):
                continue
            if kind in ("external", "relative") and self.policy.allow_external_references:
                continue
            bad = True
        if bad:
            cleaned = _CSS_URL_RE.sub(lambda mm: mm.group(0) if classify_url(mm.group(2)) == "fragment" else "none", stripped)
            return "svg.external_reference", Severity.MEDIUM, "External url() in %s" % where, cleaned
        return None

    def filter_style_text(self, el: ET.Element) -> None:
        text = "".join(el.itertext())
        verdict = self.css_verdict(text, "<style>")
        if verdict is None:
            return
        code, severity, message, replacement = verdict
        self.add(code, severity, message, element="style")
        if self.modify:
            for child in list(el):
                el.remove(child)
            el.text = _CSS_IMPORT_RE.sub("", replacement or "")

    # -- traversal -------------------------------------------------------------
    def walk(self, root: ET.Element) -> None:
        self.element_count = 1
        self.process_attributes(root)
        stack: List[Tuple[ET.Element, int]] = [(root, 1)]
        while stack:
            parent, depth = stack.pop()
            if depth > self.policy.max_depth:
                self.add("svg.too_deep", Severity.HIGH, "Element nesting deeper than %d" % self.policy.max_depth)
                if self.modify:
                    for child in list(parent):
                        parent.remove(child)
                continue
            prev: Optional[ET.Element] = None
            for child in list(parent):
                self.element_count += 1
                if self.element_count > self.policy.max_elements:
                    self.add("svg.too_many_elements", Severity.HIGH, "More than %d elements" % self.policy.max_elements)
                    if self.modify:
                        self._remove_child(parent, child, prev)
                    continue
                verdict = self.element_verdict(child)
                if verdict is not None:
                    code, severity, message = verdict
                    self.add(code, severity, message, element=_local(child.tag)[1])
                    if self.modify:
                        self._remove_child(parent, child, prev)
                        continue
                    stack.append((child, depth + 1))  # keep scanning inside for a full report
                    prev = child
                    continue
                self.process_attributes(child)
                if _local(child.tag)[1] == "style":
                    self.filter_style_text(child)
                stack.append((child, depth + 1))
                prev = child


def _preprocess(data: bytes, policy: SvgPolicy, findings: List[Finding], modify: bool) -> Optional[bytes]:
    if len(data) > policy.max_bytes:
        findings.append(Finding("svg.too_large", Severity.HIGH, "SVG larger than %d bytes" % policy.max_bytes, {"size": len(data)}))
        return None
    if _ENTITY_RE.search(data):
        findings.append(Finding("svg.entity_declaration", Severity.CRITICAL, "SVG declares XML entities (XXE / billion-laughs risk)"))
        if not modify:
            return None
    doctype = _DOCTYPE_RE.search(data)
    if doctype:
        internal_subset = doctype.group(1) is not None
        findings.append(Finding(
            "svg.doctype", Severity.MEDIUM if internal_subset else Severity.LOW,
            "SVG has a DOCTYPE%s" % (" with an internal subset" if internal_subset else ""), remediated=modify,
        ))
        data = data[: doctype.start()] + data[doctype.end() :]
    if _PI_RE.search(data):
        findings.append(Finding("svg.processing_instruction", Severity.MEDIUM, "SVG contains processing instructions (e.g. external xml-stylesheet)", remediated=modify))
        data = _PI_RE.sub(b"", data)
    if _ENTITY_RE.search(data):
        # entity declared outside a DOCTYPE we could strip: refuse to parse
        return None
    return data


def _run(data: bytes, policy: SvgPolicy, modify: bool) -> SvgResult:
    result = SvgResult()
    if isinstance(data, str):
        data = data.encode("utf-8")
    cleaned = _preprocess(bytes(data), policy, result.findings, modify)
    if cleaned is None:
        return result
    try:
        parser = ET.XMLParser()
        root = ET.fromstring(cleaned, parser=parser)
    except ET.ParseError as exc:
        result.findings.append(Finding("svg.parse_error", Severity.HIGH, "SVG is not well-formed XML: %s" % exc))
        return result
    ns, local = _local(root.tag)
    if local != "svg":
        result.findings.append(Finding("svg.not_svg", Severity.HIGH, "Root element is <%s>, not <svg>" % local))
        return result
    if ns and ns != SVG_NS:
        result.findings.append(Finding("svg.not_svg", Severity.HIGH, "Root <svg> is in namespace %s" % ns))
        return result
    sanitizer = _Sanitizer(policy, modify)
    sanitizer.walk(root)
    result.findings.extend(sanitizer.findings)
    result.element_count = sanitizer.element_count
    if modify:
        if not ns:
            root.set("xmlns", SVG_NS)
        result.sanitized = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return result


def scan_svg(data: bytes, policy: SvgPolicy = DEFAULT_POLICY) -> List[Finding]:
    """Report problems without modifying anything."""
    return _run(data, policy, modify=False).findings


def sanitize_svg(data: bytes, policy: SvgPolicy = DEFAULT_POLICY) -> SvgResult:
    """Remove dangerous content. ``result.sanitized`` is ``None`` when the input
    could not be parsed or was rejected outright (see ``result.findings``)."""
    return _run(data, policy, modify=True)


def is_svg(data: bytes) -> bool:
    from ..sniff import detect

    return detect(data[:2048]).mime == "image/svg+xml"
