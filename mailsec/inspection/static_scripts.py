"""Narrow, inert HTML-smuggling analysis. No eval, emulation, or URL access.

Decoding is restricted to literal base64 strings passed to atob/base64ToBlob.
The strong finding requires a generated script containing a shell command that
downloads a file and then launches that same file through a script interpreter.
Script presence, base64 data, and ordinary file downloads alone are not malware.
"""

import base64
import binascii
import hashlib
import re
from html.parser import HTMLParser

_IDENT = r"[A-Za-z_$][\w$]{0,512}"
_JS_TOKEN = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|//[^\r\n]*|/\*[\s\S]*?\*/''')
_LITERAL = re.compile(r'''(?P<quote>["'])(?P<data>[A-Za-z0-9+/=\r\n]{40,})(?P=quote)''')


def _without_comments(value):
    return _JS_TOKEN.sub(lambda match: " " if match.group().startswith(("//", "/*")) else match.group(), value)


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.inside = False
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.inside = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.inside = False

    def handle_data(self, value):
        if self.inside:
            self.scripts.append(value)


def inspect_html_scripts(source, result):
    parser = _Scripts()
    parser.feed(source)
    script = _without_comments("\n".join(parser.scripts))
    if not script:
        return
    result.coverage["script_analysis"] = "bounded_literal_static_analysis_only"
    # The script must actually construct a browser download, not merely mention it.
    generated = bool(re.search(r"\b(?:createObjectURL|msSaveOrOpenBlob)\s*\(", script)
                     and re.search(r"(?:\.click\s*\(|\bmsSaveOrOpenBlob\s*\()", script))
    script_download = bool(re.search(r'''(?:\.download\s*=\s*|msSaveOrOpenBlob\s*\([^,]+,\s*)["'][^"']{1,256}\.(?:js|jse|vbs|vbe|wsf|hta|ps1|cmd|bat|exe|scr)["']''', script, re.I))
    if generated:
        result.finding("html_generated_download", "generated_download",
                       "HTML programmatically generates a download; the file was not executed. "
                       "A browser-generated download alone does not establish maliciousness.", "review" if script_download else "info")
    budget = result.limits["max_static_decoded_bytes"]
    decoded_count = 0
    for match in _LITERAL.finditer(script):
        # Decode only literal assignments used by a known base64 decoder, or a
        # literal directly inside one. No general JavaScript expression evaluation.
        prefix = script[max(0, match.start() - 600):match.start()]
        assignment = re.search(rf"\b({_IDENT})\s*=\s*$", prefix)
        direct = re.search(r"\b(?:atob|base64ToBlob)\s*\(\s*$", prefix, re.I)
        if not direct and not (assignment and re.search(
                rf"\b(?:atob|base64ToBlob)\s*\(\s*{re.escape(assignment[1])}\s*[,)]", script, re.I)):
            continue
        encoded = re.sub(r"\s+", "", match["data"])
        if decoded_count >= result.limits["max_static_payloads"] or len(encoded) * 3 // 4 > budget:
            result.gap("static_decode_budget_limit")
            result.coverage["material_content_gap"] = bool(generated and script_download)
            break
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        decoded_count += 1
        budget -= len(payload)
        text = payload.decode("utf-8", errors="replace")
        code = _without_comments(text)
        result.text_urls(code)
        digest = hashlib.sha256(payload).hexdigest()
        indicators = _download_execute_indicators(code)
        result.result.setdefault("static_payloads", []).append({
            "sha256": digest, "decoded_bytes": len(payload), "encoding": "base64_literal",
            "executed": False, "indicators": indicators,
        })
        if generated and script_download and indicators:
            result.finding("static_download_execute", "static_download_execute",
                           "HTML generates a script download. Its base64-decoded script creates WScript.Shell, "
                           "uses bitsadmin to download a file, and runs that same file with wscript/cscript. "
                           f"Decoded payload SHA-256: {digest}. Nothing was executed or fetched.", "critical")
    result.coverage["static_payloads_decoded"] = decoded_count


def _download_execute_indicators(code):
    """Require shell-object and output-variable continuity across both commands."""
    shell = re.search(rf'''\b({_IDENT})\s*=\s*new\s+ActiveXObject\s*\(\s*["']WScript\.Shell["']\s*\)''', code, re.I)
    if shell is None:
        return []
    run = re.escape(shell[1]) + r"\s*\.run\s*\("
    download = re.search(run + rf'''\s*["']bitsadmin\s+/transfer\s+[^"']*["']\s*\+[^;\r\n]{{0,2500}}?\+\s*({_IDENT})\s*,\s*[01]\s*,\s*true\s*\)''', code, re.I)
    if download is None:
        return []
    execution = re.search(run + rf'''\s*["'](?:wscript|cscript)\s+[^"']*["']\s*\+\s*{re.escape(download[1])}\s*\)''', code, re.I)
    if execution is None or execution.start() <= download.start():
        return []
    return ["generated_script", "WScript.Shell", "bitsadmin_download", "same_file_script_execution"]
