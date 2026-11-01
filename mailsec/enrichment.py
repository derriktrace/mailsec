"""Deterministic identity/context enrichment; absence of reputation is neutral."""

from __future__ import annotations

import copy
import re
import unicodedata
from difflib import SequenceMatcher

from .parsing import normalize_domain, root_domain

ENRICHMENT_VERSION = "enrichment-v2"
_AUTH_RESULT = re.compile(r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b([^;]*)", re.I)
_PROP = re.compile(r"\b(smtp\.mailfrom|smtp\.helo|header\.d|header\.from|header\.i)\s*=\s*(?:\"([^\"]+)\"|([^\s;()]+))", re.I)
_BY = re.compile(r"\bby\s+([^\s;()]+)", re.I)
_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"}


def _domain_from_address(value: str | None) -> str:
    return normalize_domain((value or "").rsplit("@", 1)[-1])


def _belongs(domain: str, trusted: str) -> bool:
    # PSL root equality would over-trust sibling hosted tenants. Match exact authorized trees.
    domain, trusted = normalize_domain(domain), normalize_domain(trusted)
    return bool(domain and trusted and (domain == trusted or domain.endswith("." + trusted)))


def _name(value: str) -> str:
    return " ".join(re.findall(r"\w+", unicodedata.normalize("NFKC", value).casefold()))


def _claimed_name(display_name: str, known_name: str) -> bool:
    displayed, known = _name(display_name), _name(known_name)
    return bool(known and (displayed == known or f" {known} " in f" {displayed} "))


def _parse_auth_value(value: str) -> dict:
    # Strip comments to prevent 'dkim=pass' nested in explanatory text being parsed.
    value = re.sub(r"\([^()]*\)", " ", value.replace("\r", " ").replace("\n", " "))
    authserv_tokens = value.split(";", 1)[0].split()
    output = {"authserv_id": normalize_domain(authserv_tokens[0]) if authserv_tokens else "", "results": []}
    for match in _AUTH_RESULT.finditer(value):
        method, result, tail = match.groups()
        props = {key.lower(): (quoted or bare) for key, quoted, bare in _PROP.findall(tail)}
        method, result = method.lower(), result.lower()
        domain_value = props.get({"spf": "smtp.mailfrom", "dkim": "header.d", "dmarc": "header.from"}[method])
        if not domain_value and method == "spf":
            domain_value = props.get("smtp.helo")
        if not domain_value and method == "dkim":
            domain_value = props.get("header.i")
        output["results"].append({"method": method, "result": result if result in _RESULTS else "unknown", "domain": _domain_from_address(domain_value) or None})
    return output


def _authentication(evidence: dict, organization: dict) -> dict:
    headers = evidence.get("authentication", {}).get("transport_headers", [])
    candidates = [{"header_index": row["index"], **_parse_auth_value(row["value"])} for row in headers if row["name"] == "authentication-results"]
    trusted = {normalize_domain(item) for item in organization.get("trusted_authserv_ids", [])}
    selected = None
    reason = "Uploaded/imported headers are untrusted assertions; no authentication verification was performed."
    if evidence["message"].get("provider") == "gmail" and trusted and not evidence.get("quality", {}).get("headers_truncated"):
        # Gmail inserts its ingress Received followed by its own Authentication-Results.
        # Restrict to that contiguous receiving block, never a sender's lower Received block.
        boundaries = [row for row in headers if row["name"] == "received"]
        boundary = None
        for row in boundaries:
            match = _BY.search(row["value"])
            if re.search(r"\bfrom\s+", row["value"], re.I):
                boundary = row if match and normalize_domain(match.group(1)) in trusted else None
                break
        if boundary:
            next_index = min((row["index"] for row in boundaries if row["index"] > boundary["index"]), default=10**9)
            block = [item for item in candidates if boundary["index"] < item["header_index"] < next_index]
            if block and block[0]["authserv_id"] in trusted:
                selected = block[0]
                reason = "First receiver Authentication-Results in the configured Gmail ingress block; Gmail API transport provenance is required."
            else:
                reason = "No configured receiver Authentication-Results at the Gmail ingress boundary; authentication remains unknown."
        else:
            reason = "Could not locate a configured Gmail ingress boundary; authentication remains unknown."
    elif evidence["message"].get("provider") == "gmail":
        reason = "No trusted receiver configured, or transport headers were truncated; authentication remains unknown."
    sender_domain = evidence["message"]["sender"]["domain"]
    result = {
        "status": "receiver_reported" if selected else "unverified", "provenance": reason,
        "trusted_authserv_id": selected["authserv_id"] if selected else None,
        "spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
        "spf_domain": None, "dkim_domain": None, "dmarc_domain": None,
        "spf_aligned": None, "dkim_aligned": None, "alignment_mode": "relaxed_registered_domain",
        "from_return_path_match": None, "from_reply_to_match": None,
        "unverified_header_assertions": candidates, "transport_headers": headers,
        "limitations": ["No independent SPF/DKIM/DMARC or ARC verification.", "Authentication establishes domain control, not ownership of a claimed brand."],
    }
    if selected:
        for method in ("spf", "dkim", "dmarc"):
            rows = [row for row in selected["results"] if row["method"] == method]
            # Multiple DKIM signatures: prefer an aligned passing signature, then any pass.
            rows.sort(key=lambda row: (row["result"] == "pass" and root_domain(row["domain"] or "") == root_domain(sender_domain), row["result"] == "pass"), reverse=True)
            if rows:
                row = rows[0]
                result[method] = row["result"]
                result[method + "_domain"] = row["domain"]
                if method in {"spf", "dkim"} and row["domain"] and sender_domain:
                    result[method + "_aligned"] = root_domain(row["domain"]) == root_domain(sender_domain)
        result["receiver_results"] = selected["results"]
    for key, field in (("from_return_path_match", "return_path"), ("from_reply_to_match", "reply_to")):
        other = evidence["message"].get(field)
        if other and sender_domain:
            result[key] = root_domain(_domain_from_address(other)) == root_domain(sender_domain)
    return result


def _lookalikes(domain: str, domains: list[str]) -> list[dict]:
    if not domain:
        return []
    findings = []
    try:
        unicode_domain = domain.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        unicode_domain = domain
    skeleton = unicode_domain.casefold().replace("rn", "m").replace("0", "o").replace("1", "l")
    for target in sorted(set(domains)):
        if _belongs(domain, target):
            continue
        target_root = root_domain(target)
        target_label = target_root.split(".", 1)[0]
        source_label = root_domain(domain).split(".", 1)[0]
        similarity = SequenceMatcher(None, root_domain(domain), target_root).ratio()
        match = (
            len(target_label) >= 4 and target_label in source_label
            or len(target_root) >= 6 and similarity >= 0.84
            or skeleton == target_root
        )
        if match:
            findings.append({"domain": domain, "target": target, "similarity": round(similarity, 3), "status": "heuristic_hint", "affirmatively_malicious": False})
    return findings[:20]


def _coverage(observed: bool, targets: int) -> dict:
    """A false comparison is meaningful only after a comparison was possible."""
    return {"status": "evaluated" if observed and targets else "not_evaluated",
            "target_count": targets,
            "reason": "Compared only with configured targets." if observed and targets
            else "No configured comparison targets." if not targets else "Observed value is unavailable."}


def _claimed_domain_match(domain: str, claimed: list[str], domains: dict[str, list[str]]) -> bool | None:
    if not domain or not claimed:
        return None
    checks = [any(_belongs(domain, target) for target in domains[name]) for name in claimed if domains[name]]
    if any(not result for result in checks):
        return False
    return True if len(checks) == len(claimed) else None


def enrich(evidence: dict, organization: dict, history: dict | None = None) -> dict:
    """Return a copied evidence object; history values are supplied by the datastore."""
    result = copy.deepcopy(evidence)
    if "organization" in organization and isinstance(organization["organization"], dict):
        organization = organization["organization"]
    result["enrichment_version"] = ENRICHMENT_VERSION
    message = result["message"]
    sender = message["sender"]
    display_name, domain = sender["display_name"], sender["domain"]
    internal_domains = sorted({normalized for item in organization.get("domains", []) if (normalized := normalize_domain(item))})
    vendors = organization.get("known_vendors", {})
    domains_by_vendor = {name: sorted({normalized for item in vendor.get("domains", []) if (normalized := normalize_domain(item))})
                         for name, vendor in vendors.items()}
    vendor_domains = sorted({domain for domains in domains_by_vendor.values() for domain in domains})
    comparison_domains = sorted(set(internal_domains + vendor_domains))
    named_executives = [item for item in organization.get("executives", []) if item.get("name", "").strip()]
    claimed_vendors = [name for name in vendors if _claimed_name(display_name, name)]
    vendor_matches = [name for name, domains in domains_by_vendor.items() if any(_belongs(domain, trusted) for trusted in domains)]
    claimed_executives = [item for item in named_executives if _claimed_name(display_name, item["name"])]
    contradictions = []
    for vendor in claimed_vendors:
        if domain and domains_by_vendor[vendor] and vendor not in vendor_matches:
            contradictions.append({"kind": "known_vendor_display_name", "claimed_identity": vendor, "observed_domain": domain, "expected_domains": vendors[vendor].get("domains", []), "interpretation": "Identity mismatch requires context; not affirmative maliciousness by itself."})
    for executive in claimed_executives:
        if sender["address"] and executive.get("email") and sender["address"].casefold() != executive["email"].casefold():
            contradictions.append({"kind": "internal_person_display_name", "claimed_identity": executive.get("name"), "observed_address": sender["address"], "expected_address": executive.get("email"), "interpretation": "Name overlap or an alternate address is possible; assess the requested action and other evidence."})
    lookalikes = _lookalikes(domain, comparison_domains)
    reply_to = message.get("reply_to")
    identity = {
        "display_name_matches_internal_user": bool(claimed_executives) if named_executives and display_name else None,
        "display_name_matches_known_vendor": bool(claimed_vendors) if vendors and display_name else None,
        "sender_domain_matches_known_vendor": bool(vendor_matches) if vendor_domains and domain else None,
        "sender_claimed_vendor_domain_match": _claimed_domain_match(domain, claimed_vendors, domains_by_vendor),
        "sender_domain_is_internal": any(_belongs(domain, own) for own in internal_domains) if internal_domains and domain else None,
        "claimed_vendors": claimed_vendors, "matched_vendors": vendor_matches,
        "identity_contradictions": contradictions, "lookalike_domain": bool(lookalikes) if comparison_domains and domain else None,
        "lookalike_target": lookalikes[0]["target"] if lookalikes else None, "lookalike_hints": lookalikes,
        "contains_punycode": "xn--" in domain if domain else None,
        "reply_to_mismatch": root_domain(_domain_from_address(reply_to)) != sender["root_domain"] if reply_to and domain else None,
        "comparison_coverage": {
            "scope": "Configured display names and domains only; message-body identity claims, arbitrary brands, ownership and authorization were not verified. An unevaluated check is unknown, not evidence against impersonation.",
            "internal_display_name": _coverage(bool(display_name), len(named_executives)),
            "vendor_display_name": _coverage(bool(display_name), len(vendors)),
            "vendor_sender_domain": _coverage(bool(domain), len(vendor_domains)),
            "internal_sender_domain": _coverage(bool(domain), len(internal_domains)),
            "sender_lookalike": _coverage(bool(domain), len(comparison_domains)),
        },
        "history_status": "available" if history is not None else "not_available",
        "sender_first_seen": None, "sender_messages_previous_90d": None, "domain_messages_previous_90d": None,
    }
    context = {
        "internal_domains": internal_domains, "known_vendor_domains": vendor_domains,
        "recipient_has_communicated_with_sender_before": None,
        "recipient_has_communicated_with_sender_domain_before": None,
        "existing_thread": None,
        "history_limitations": "Counts describe the locally ingested corpus, not the complete mailbox history. Missing history is neutral.",
    }
    if history is not None:
        for key in ("sender_first_seen", "sender_messages_previous_90d", "domain_messages_previous_90d", "sender_first_seen_at", "sender_last_seen_at", "sender_messages_previous_7d", "sender_messages_previous_30d", "domain_messages_previous_7d", "domain_messages_previous_30d", "first_observed_sender", "last_observed_sender", "previous_verdicts"):
            if key in history:
                identity[key] = history[key]
        for key in ("recipient_has_communicated_with_sender_before", "recipient_has_communicated_with_sender_domain_before", "existing_thread", "recipient_received_from_sender_before", "number_of_observed_recipients", "coverage", "complete_90d_history"):
            if key in history:
                context[key] = history[key]
    result["authentication"] = _authentication(result, organization)
    result["identity"] = identity
    result["organization_context"] = context
    links = result.get("links", [])
    evaluated_links = sum(bool(link.get("domain")) for link in links) if comparison_domains else 0
    identity["comparison_coverage"]["link_lookalike"] = {
        "status": "evaluated" if links and evaluated_links == len(links) else "partial" if evaluated_links else "not_evaluated",
        "target_count": len(comparison_domains), "evaluated_links": evaluated_links, "total_links": len(links),
    }
    for link in links:
        link_domain = link.get("domain", "")
        link["lookalike_hints"] = _lookalikes(link_domain, comparison_domains) if comparison_domains and link_domain else None
        claimed = [name for name in vendors if _claimed_name(link.get("display_text", ""), name)]
        link["display_text_brand_claims"] = claimed if vendors and link.get("display_text") else None
        link["claimed_brand_domain_matches"] = {name: _claimed_domain_match(link_domain, [name], domains_by_vendor) for name in claimed} if claimed else None
    return result
