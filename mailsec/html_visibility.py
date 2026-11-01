"""Bounded offline HTML evidence extraction, never a browser or CSS interpreter.

Supports ordinary email selectors and visibility declarations. Unsupported hiding
rules and work limits are explicit coverage gaps; no network resources are loaded.
Hidden text is evidence, but is not asserted to be malicious (preheaders are common).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

MAX_NODES = 20_000
MAX_DEPTH = 128
MAX_CSS_CHARS = 256_000
MAX_RULES = 2_048
MAX_SELECTOR_CHECKS = 400_000
MAX_OUTPUT_CHARS = 200_000
MAX_URLS = 2_000
MAX_SOURCE_CHARS = 2_000_000
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_BLOCK = {"p", "div", "br", "tr", "li", "hr", "h1", "h2", "h3", "h4", "section", "blockquote", "table"}
_NONCONTENT = {"head", "script", "style", "template", "title"}
_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.I)
_ZERO = re.compile(r"^[+-]?0+(?:\.0+)?(?:px|pt|em|rem|%|in|cm|mm)?$")
_DECLARATIONS = {"display", "visibility", "opacity", "height", "max-height", "width", "max-width", "overflow", "overflow-y", "font-size", "clip", "clip-path"}
_SIMPLE = re.compile(r"^(?:[\w-]+|\*)?(?:(?:[.#][\w-]+)|(?:\[[\w-]+(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[\w-]+))?\]))*$")


def clean_text(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\x00", "")
    value = "\n".join(re.sub(r"[^\S\n]+", " ", line).strip() for line in value.split("\n"))
    return re.sub(r"\n{3,}", "\n\n", value).strip()


@dataclass
class _Node:
    tag: str
    attrs: dict[str, str]
    parent: int
    previous_sibling: int = 0
    text: list[str] = field(default_factory=list)
    structural_hidden: bool = False
    blocked: bool = False
    visibility: str = "visible"
    font_zero: bool = False
    quoted: bool = False
    anchor: int | None = None
    anchor_text: list[str] = field(default_factory=list)
    anchor_images: list[dict] = field(default_factory=list)
    anchor_visible: bool = False


def _declarations(value: str) -> dict[str, tuple[str, bool]]:
    result = {}
    for declaration in value.split(";"):
        name, separator, val = declaration.partition(":")
        name = name.strip().lower()
        if not separator or name not in _DECLARATIONS:
            continue
        important = bool(re.search(r"!\s*important\s*$", val, re.I))
        val = re.sub(r"!\s*important\s*$", "", val, flags=re.I).strip().lower()
        if name not in result or important or not result[name][1]:
            result[name] = (val, important)
    return result


def _hiding(declarations: dict[str, tuple[str, bool]]) -> bool:
    return any((name == "display" and value == "none") or (name == "visibility" and value in {"hidden", "collapse"})
               or name in {"clip", "clip-path"} or (name in {"opacity", "font-size"} and _ZERO.fullmatch(value))
               for name, (value, _) in declarations.items())


def _matches_simple(node: _Node, selector: str) -> bool:
    without_attributes = re.sub(r"\[[^\]]*\]", "", selector)
    tag = re.match(r"^[\w-]+|^\*", selector)
    if tag and tag.group() != "*" and node.tag != tag.group().lower():
        return False
    for id_value in re.findall(r"#([\w-]+)", without_attributes):
        if node.attrs.get("id") != id_value:
            return False
    classes = set(node.attrs.get("class", "").split())
    if any(value not in classes for value in re.findall(r"\.([\w-]+)", without_attributes)):
        return False
    for field_name, raw_value in re.findall(r"\[([\w-]+)(?:\s*=\s*([^\]]+))?\]", selector):
        if field_name not in node.attrs:
            return False
        if raw_value and node.attrs[field_name] != raw_value.strip().strip("\"'"):
            return False
    return True


def _selector_parts(selector: str):
    # Whitespace inside an attribute equality is normalized before tokenization.
    selector = re.sub(r"\[\s*([\w-]+)\s*=\s*([^\]]+)\]", lambda m: "[" + m[1] + "=" + m[2].strip() + "]", selector)
    parts = re.findall(r"(?:\[[^\]]*\]|[^\s>+])+|[>+]", selector.strip())
    combinators = {">", "+"}
    if (not parts or parts[0] in combinators or parts[-1] in combinators
            or any(not _SIMPLE.fullmatch(part) for part in parts if part not in combinators)):
        return None
    if any(a in combinators and b in combinators for a, b in zip(parts, parts[1:])):
        return None
    return parts


class _Document(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.nodes = [_Node("document", {}, 0)]
        self.stack = [0]
        self.last_child: dict[int, int] = {}
        self.events: list[tuple[int, str]] = []
        self.limits: set[str] = set()
        self.unsupported_hiding = False
        self.visibility_uncertainties: set[str] = set()
        self.stopped = False

    def handle_starttag(self, tag, attrs):
        if self.stopped:
            return
        if len(self.nodes) >= MAX_NODES or len(self.stack) >= MAX_DEPTH:
            self.limits.add("html_structure_limit")
            self.stopped = True
            return
        # Repair common optional-end tags rather than hiding a subsequent sibling.
        if tag in {"p", "li", "tr", "td", "th"} and self.nodes[self.stack[-1]].tag == tag:
            self.stack.pop()
        index = len(self.nodes)
        parent = self.stack[-1]
        self.nodes.append(_Node(tag, {k: (v or "") for k, v in attrs}, parent,
                                previous_sibling=self.last_child.get(parent, 0)))
        self.last_child[parent] = index
        self.events.append((index, "\n" if tag in _BLOCK else ""))
        if tag not in _VOID:
            self.stack.append(index)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.stopped:
            return
        for pos in range(len(self.stack) - 1, 0, -1):
            if self.nodes[self.stack[pos]].tag == tag:
                index = self.stack[pos]
                if tag in _BLOCK:
                    self.events.append((index, "\n"))
                del self.stack[pos:]
                break

    def handle_data(self, data):
        if not self.stopped:
            index = self.stack[-1]
            self.nodes[index].text.append(data)
            self.events.append((index, data))

    def _rules(self):
        css = "\n".join("".join(node.text) for node in self.nodes if node.tag == "style")
        if len(css) > MAX_CSS_CHARS:
            self.limits.add("css_source_limit")
        css = re.sub(r"/\*.*?\*/", "", css[:MAX_CSS_CHARS], flags=re.S).replace("<!--", "").replace("-->", "")
        rules, context, start = [], [], 0
        # Flat rules apply. Conditional @media/@supports are recorded as ambiguous
        # only when they contain hiding; never assume one recipient viewport.
        for match in re.finditer(r"[{}]", css):
            if match.group() == "{":
                context.append(css[start:match.start()].strip())
                start = match.end()
                continue
            if not context:
                start = match.end()
                continue
            selector = context.pop()
            declarations = _declarations(css[start:match.start()])
            start = match.end()
            if not declarations:
                continue
            if context or selector.startswith("@"):
                if not selector.startswith(("@font-face", "@page")) and _hiding(declarations):
                    self.unsupported_hiding = True
                    self.visibility_uncertainties.add("conditional_visibility")
                continue
            for value in selector.split(","):
                parts = _selector_parts(value)
                if not parts:
                    self.unsupported_hiding |= _hiding(declarations)
                    if _hiding(declarations):
                        self.visibility_uncertainties.add("unsupported_visibility_selector")
                    continue
                if len(rules) >= MAX_RULES:
                    self.limits.add("css_rule_limit")
                    return rules
                specificity = (value.count("#"), value.count(".") + value.count("["),
                               sum(bool(re.match(r"^[\w-]+", part)) for part in parts if part not in {">", "+"}))
                rules.append((parts, specificity, declarations))
        return rules

    def _matches(self, index, parts):
        if not _matches_simple(self.nodes[index], parts[-1]):
            return False
        pos = len(parts) - 2
        while pos >= 0:
            combinator = parts[pos] if parts[pos] in {">", "+"} else None
            if combinator:
                pos -= 1
            index = (self.nodes[index].previous_sibling if combinator == "+"
                     else self.nodes[index].parent)
            while index and not _matches_simple(self.nodes[index], parts[pos]):
                if combinator:
                    return False
                index = self.nodes[index].parent
            if not index:
                return False
            pos -= 1
        return True

    def finish(self) -> dict:
        rules = self._rules()
        checks = 0
        for index, node in enumerate(self.nodes[1:], 1):
            parent = self.nodes[node.parent]
            winners = {}
            for order, (parts, specificity, declarations) in enumerate(rules):
                checks += 1
                if checks > MAX_SELECTOR_CHECKS:
                    self.limits.add("css_match_limit")
                    break
                if self._matches(index, parts):
                    for name, (value, important) in declarations.items():
                        rank = (important, 0, *specificity, order)
                        if name not in winners or rank >= winners[name][0]:
                            winners[name] = (rank, value)
            for name, (value, important) in _declarations(node.attrs.get("style", "")).items():
                rank = (important, 1, 0, 0, 0, 0)
                if name not in winners or rank >= winners[name][0]:
                    winners[name] = (rank, value)
            style = {name: value for name, (_, value) in winners.items()}
            if any(name in {"display", "visibility", "opacity"} and ("var(" in value or "calc(" in value)
                   for name, value in style.items()):
                self.unsupported_hiding = True
                self.visibility_uncertainties.add("unresolved_visibility_value")
            if "clip-path" in style:
                self.unsupported_hiding = True
                self.visibility_uncertainties.add("unsupported_clipping")
            node.structural_hidden = parent.structural_hidden or node.tag in _NONCONTENT
            clipped = (style.get("overflow") == "hidden" or style.get("overflow-y") == "hidden") and any(
                _ZERO.fullmatch(style.get(key, "")) for key in ("height", "max-height"))
            clipped |= bool(re.fullmatch(r"rect\(\s*0(?:px)?[ ,]+0(?:px)?[ ,]+0(?:px)?[ ,]+0(?:px)?\s*\)", style.get("clip", "")))
            node.blocked = parent.blocked or "hidden" in node.attrs or style.get("display") == "none" or bool(_ZERO.fullmatch(style.get("opacity", ""))) or clipped
            node.visibility = style.get("visibility", parent.visibility)
            if node.visibility in {"inherit", "unset"}:
                node.visibility = parent.visibility
            elif node.visibility in {"initial", "revert"}:
                node.visibility = "visible"
            node.font_zero = bool(_ZERO.fullmatch(style["font-size"])) if "font-size" in style and style["font-size"] not in {"inherit", "unset"} else parent.font_zero
            node.quoted = parent.quoted or node.tag == "blockquote" or bool(set(node.attrs.get("class", "").split()) & {"gmail_quote", "yahoo_quoted", "protonmail_quote"})
            node.anchor = index if node.tag == "a" and node.attrs.get("href") else parent.anchor
        visible, hidden, quoted, links, images = [], [], [], [], []

        def visibility(node, text=False):
            return "noncontent" if node.structural_hidden else "hidden" if node.blocked or node.visibility in {"hidden", "collapse"} or (text and node.font_zero) else "visible"

        def add_link(url, node, source, display="", image_context=None):
            if len(links) >= MAX_URLS:
                self.limits.add("html_url_limit")
                return
            links.append({"raw_url": url, "display_text": display, "source": source,
                          "visibility": visibility(node), "quoted_context": node.quoted,
                          "image_context": image_context or []})

        for index, text in self.events:
            node = self.nodes[index]
            state = visibility(node, text=node.tag != "img")
            if state == "noncontent":
                for match in _URL.finditer(text):
                    add_link(match.group().rstrip(".,;!?)"), node, "html_nonvisible_source")
                continue
            if node.tag == "img" and state == "visible" and node.attrs.get("alt"):
                text += "\n[Image description: " + node.attrs["alt"][:1000] + "]\n"
            (hidden if state == "hidden" else quoted if node.quoted else visible).append(text)
            if node.anchor is not None and state == "visible":
                self.nodes[node.anchor].anchor_text.append(text)
                if text.strip():
                    self.nodes[node.anchor].anchor_visible = True
        for node in self.nodes[1:]:
            state = visibility(node)
            if node.tag == "img":
                image = {"src": node.attrs.get("src", "")[:8192], "alt": node.attrs.get("alt", "")[:1000],
                         "visibility": state, "quoted_context": node.quoted,
                         "width": node.attrs.get("width"), "height": node.attrs.get("height")}
                if len(images) < 200:
                    images.append(image)
                if node.anchor is not None:
                    self.nodes[node.anchor].anchor_images.append(image)
                    if state == "visible":
                        self.nodes[node.anchor].anchor_visible = True
            for name in ("src", "action", "formaction", "poster", "data", "background"):
                if node.attrs.get(name):
                    add_link(node.attrs[name], node, f"html_{node.tag}_{name}")
            if node.tag != "a" and node.attrs.get("href"):
                add_link(node.attrs["href"], node, f"html_{node.tag}_href")
            for candidate in node.attrs.get("srcset", "").split(","):
                if candidate.strip():
                    add_link(candidate.strip().split()[0], node, f"html_{node.tag}_srcset")
            for match in _URL.finditer(node.attrs.get("style", "")):
                add_link(match.group().rstrip(".,;!?)"), node, "html_style_resource")
        for node in self.nodes:
            if node.tag == "a" and node.attrs.get("href"):
                # Hidden anchors remain evidence but cannot masquerade as visible CTAs.
                previous_count = len(links)
                add_link(node.attrs["href"], node, "html_anchor", clean_text("".join(node.anchor_text)), node.anchor_images[:20])
                if node.anchor_visible and len(links) > previous_count:
                    links[-1]["visibility"] = "visible"
        texts = {"visible_text": clean_text("".join(visible)), "hidden_text": clean_text("".join(hidden)),
                 "quoted_text": clean_text("".join(quoted))}
        counts = {name + "_chars": len(value) for name, value in texts.items()}
        if any(len(value) > MAX_OUTPUT_CHARS for value in texts.values()):
            self.limits.add("html_output_limit")
        findings = []
        if len(texts["hidden_text"]) > max(1000, 3 * len(texts["visible_text"])):
            findings.append("hidden_text_dominates_visible")
        if any(image["visibility"] == "visible" and not image["alt"] for image in images):
            findings.append("visible_image_without_text")
        if self.unsupported_hiding:
            findings.append("unsupported_or_conditional_visibility_rule")
        return {**{name: value[:MAX_OUTPUT_CHARS] for name, value in texts.items()},
                "links": links, "images": images, "counts": counts, "findings": findings,
                "coverage": "partial" if self.limits or self.unsupported_hiding else "supported_static_rules",
                "limits": sorted(self.limits), "unsupported_hiding": self.unsupported_hiding,
                "visibility_uncertainties": sorted(self.visibility_uncertainties)}


def material_image_gap(extracted: dict, *, schemes: tuple[str, ...]) -> bool:
    """Identify unread image-focused content without decoding or fetching it.

    Match the existing remote-image scope: short visible copy plus a substantial
    unquoted visible image. Small decorations and tracking pixels are neutral.
    Dimensions are untrusted HTML strings, so never convert unbounded integers.
    """
    if len(extracted.get("visible_text", "")) >= 200:
        return False
    clickable = {image["src"] for link in extracted.get("links", [])
                 if link.get("source") == "html_anchor" and link.get("visibility") == "visible"
                 for image in link.get("image_context", [])}
    for image in extracted.get("images", []):
        if (image.get("visibility") != "visible" or image.get("quoted_context")
                or not image.get("src", "").lower().startswith(schemes)):
            continue
        dimensions = [int(value) if isinstance(value, str) and re.fullmatch(r"[0-9]{1,6}", value)
                      else None for value in (image.get("width"), image.get("height"))]
        if any(value is not None and value <= 2 for value in dimensions):
            continue
        if (dimensions[0] is None and dimensions[1] is not None and dimensions[1] <= 48
                and image["src"] not in clickable):
            continue
        if not all(value is not None and value <= 96 for value in dimensions):
            return True
    return False


def extract_html(source: str) -> dict:
    document = _Document()
    if len(source) > MAX_SOURCE_CHARS:
        document.limits.add("html_source_limit")
    try:
        document.feed(source[:MAX_SOURCE_CHARS])
        document.close()
    except (ValueError, RecursionError):
        document.limits.add("html_parse_error")
    return document.finish()
