"""Optional recipient-address pseudonyms for the model view, never local evidence.

This is deliberately not an anonymity guarantee. Names, domains, signatures,
unrecognized addresses and other identifying information can remain. The caller
must collect envelope recipients before compact model views discard them.
"""
from __future__ import annotations

import re
from collections import deque
from copy import deepcopy
from email.parser import HeaderParser
from email.utils import getaddresses
from urllib.parse import quote

from .jev import JevError

VERSION = "recipient-address-mask-v1"
MAX_RECIPIENTS = 1024
MAX_ADDRESS_CHARS = 320
MAX_PATTERN_CHARACTERS = 2_000_000
MAX_MATCHER_NODES = 200_000
MAX_MATCHER_OUTPUTS = 100_000
_ADDRESS = re.compile(r"[^\s<>@\x00-\x1f\x7f]+@[^\s<>@\x00-\x1f\x7f]+\Z")
_FIELDS = ("recipients", "to", "cc", "bcc", "to_addresses", "cc_addresses", "bcc_addresses")
LIMITATIONS = (
    "Only known recipient and connected-mailbox email addresses are replaced. "
    "Names, signatures, domains, unrecognized or differently encoded addresses and other identifiers may remain. "
    "This is pseudonymization, not anonymization. Masking can reduce detection accuracy and changes any "
    "model-view URLs containing a matched address; original evidence and local checks remain unchanged."
)


class _AddressMatcher:
    """Bounded Aho–Corasick matching; no recipient-controlled regex backtracking."""
    def __init__(self, variants):
        self.edges, self.failure, self.outputs = [{}], [0], [[]]
        if sum(len(value) for value in variants) > MAX_PATTERN_CHARACTERS:
            raise JevError("Recipient masking exceeds its safe pattern budget; no request was sent")
        for value, replacement in variants.items():
            node = 0
            folded = value.casefold()
            for char in folded:
                if char not in self.edges[node]:
                    if len(self.edges) >= MAX_MATCHER_NODES:
                        raise JevError("Recipient masking exceeds its safe matcher budget; no request was sent")
                    self.edges[node][char] = len(self.edges)
                    self.edges.append({})
                    self.failure.append(0)
                    self.outputs.append([])
                node = self.edges[node][char]
            self.outputs[node].append((len(folded), replacement))
        queue = deque(self.edges[0].values())
        output_count = sum(map(len, self.outputs))
        while queue:
            node = queue.popleft()
            for char, child in self.edges[node].items():
                queue.append(child)
                fail = self.failure[node]
                while fail and char not in self.edges[fail]:
                    fail = self.failure[fail]
                self.failure[child] = self.edges[fail].get(char, 0)
                inherited = self.outputs[self.failure[child]]
                output_count += len(inherited)
                if output_count > MAX_MATCHER_OUTPUTS:
                    raise JevError("Recipient masking exceeds its safe match budget; no request was sent")
                self.outputs[child].extend(inherited)

    def replace(self, value):
        if not self.edges[0]:
            return value, 0
        # Case folding can expand a Unicode character. Track original offsets so
        # replacement never cuts a character or changes unrelated source text.
        folded, starts, ends = [], [], []
        for index, char in enumerate(value):
            for part in char.casefold():
                folded.append(part)
                starts.append(index)
                ends.append(index + 1)
        best, node = {}, 0
        for index, char in enumerate(folded):
            while node and char not in self.edges[node]:
                node = self.failure[node]
            node = self.edges[node].get(char, 0)
            for length, replacement in self.outputs[node]:
                start, end = starts[index - length + 1], ends[index]
                if start not in best or end > best[start][0]:
                    best[start] = (end, replacement)
        result, position, count = [], 0, 0
        for start in sorted(best):
            if start < position:
                continue
            end, replacement = best[start]
            result.extend((value[position:start], replacement))
            position, count = end, count + 1
        result.append(value[position:])
        return "".join(result), count


def collect_recipient_addresses(evidence):
    """Use supplied envelope fields, never guess that every body address is a recipient."""
    message = evidence.get("message", {})
    if not isinstance(message, dict):
        message = {}
    values = []
    mailbox = message.get("mailbox")
    if isinstance(mailbox, str) and mailbox.strip():
        values.append(mailbox)
    for key in _FIELDS:
        value = message.get(key, [])
        values.extend([value] if isinstance(value, str) else value if isinstance(value, list) else [])
    # Pasted comparison text may supply a complete header block but no parsed
    # envelope. Inspect its first bounded header block only, not arbitrary prose.
    body = evidence.get("body", "")
    if isinstance(body, str):
        block = re.split(r"\r?\n\r?\n", body[:48_000], maxsplit=1)[0]
        if re.match(r"^[A-Za-z][A-Za-z-]*:", block):
            try:
                headers = HeaderParser().parsestr(block + "\n\n", headersonly=True)
                for name in ("To", "Cc", "Bcc"):
                    values.extend(headers.get_all(name, []))
            except (ValueError, TypeError, RecursionError):
                raise JevError("Recipient headers could not be read for address masking; no request was sent") from None
    addresses = set()
    for value in values:
        if isinstance(value, dict):
            value = value.get("address", "")
        if not isinstance(value, str):
            continue
        # Parse one bounded header at a time. Never silently shorten a possible
        # address or truncate the recipient set and then send it unmasked.
        if len(value) > 48_000:
            raise JevError("Recipient information exceeds the address-masking limit; no request was sent")
        try:
            parsed = getaddresses([value], strict=False)
        except (ValueError, TypeError, RecursionError):
            raise JevError("Recipient addresses could not be read for masking; no request was sent") from None
        for _, address in parsed:
            address = address.strip().lower()
            if not address:
                continue
            if len(address) > MAX_ADDRESS_CHARS:
                raise JevError("A recipient address exceeds the masking limit; no request was sent")
            if _ADDRESS.fullmatch(address):
                addresses.add(address)
            if len(addresses) > MAX_RECIPIENTS:
                raise JevError("Too many recipient addresses for safe masking; no request was sent")
    return tuple(sorted(addresses))


def mask_payload(state, questions, addresses):
    """Return independent request copies and a nonidentifying masking audit.

    Every occurrence of a known address is replaced in nested text, including
    URLs, extracted document text, dictionary keys and custom question wording.
    Common complete percent encodings (up to three rounds) are also recognized.
    No mapping back to original addresses is included in the outbound view.
    """
    addresses = tuple(addresses)
    if len(addresses) > MAX_RECIPIENTS or any(
            not isinstance(address, str) or len(address) > MAX_ADDRESS_CHARS or not _ADDRESS.fullmatch(address)
            for address in addresses):
        raise JevError("Recipient addresses exceed the masking contract; no request was sent")
    addresses = tuple(sorted(set(address.lower() for address in addresses)))
    variants = {}
    for index, address in enumerate(addresses, 1):
        replacement = f"recipient-{index}@masked.invalid"
        original = address
        for _ in range(4):
            variants.setdefault(original.lower(), replacement)
            original = quote(original, safe="")
            replacement = quote(replacement, safe="")
    matcher = _AddressMatcher(variants)
    replacements = 0

    def replace_text(value):
        nonlocal replacements
        result, count = matcher.replace(value)
        replacements += count
        return result

    def transform(value):
        if isinstance(value, str):
            return replace_text(value)
        if isinstance(value, list):
            return [transform(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                masked_key = replace_text(key) if isinstance(key, str) else key
                if masked_key in result:
                    raise JevError("Address masking would merge distinct evidence fields; no request was sent")
                result[masked_key] = transform(item)
            return result
        return deepcopy(value)

    masked_state, masked_questions = transform(state), transform(questions)
    metadata = {"enabled": True, "version": VERSION, "known_recipient_count": len(addresses),
                "replacement_count": replacements,
                "status": "known_addresses_masked" if addresses else "no_known_recipient_addresses",
                "limitations": LIMITATIONS}
    if isinstance(masked_state, dict):
        masked_state["recipient_address_privacy"] = deepcopy(metadata)
    return masked_state, masked_questions, metadata
