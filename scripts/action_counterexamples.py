"""Build label-free synthetic action/authority controls; never calls a model.

Scoring expectations live in a different fixture and are deliberately not read by
this module. These are development counterexamples, not an accuracy benchmark.
All identities and independently supplied business facts are fictional.
"""
import argparse
import copy
import json
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import parseaddr
from pathlib import Path

from mailsec.enrichment import enrich
from mailsec.parsing import parse_email

INPUT_PATH = Path(__file__).resolve().parents[1] / 'tests/fixtures/action_counterexamples/inputs.json'
_FIELDS = {'id', 'sender', 'subject', 'body', 'html', 'business_context'}


def load_inputs(path=INPUT_PATH):
    rows = json.loads(Path(path).read_text())
    if not isinstance(rows, list) or len({row['id'] for row in rows}) != len(rows):
        raise ValueError('Expected unique opaque fixture identifiers')
    for row in rows:
        if set(row) - _FIELDS or not {'id', 'sender', 'subject', 'body'} <= set(row):
            raise ValueError('Only message inputs and independent business facts are permitted')
    return rows


def build_raw(row):
    """Create a reproducible receiver-delivered MIME message, without its case ID."""
    if set(row) - _FIELDS:
        raise ValueError('Scoring metadata must not enter the input builder')
    domain = parseaddr(row['sender'])[1].rsplit('@', 1)[-1]
    message = EmailMessage(policy=SMTP)
    message['Received'] = f'from outbound.{domain} by mx.google.com; Mon, 12 Oct 2026 12:00:00 +0000'
    message['Authentication-Results'] = (
        f'mx.google.com; spf=pass smtp.mailfrom={domain}; '
        f'dkim=pass header.d={domain}; dmarc=pass header.from={domain}'
    )
    message['From'] = row['sender']
    message['To'] = 'analyst@customer.example'
    message['Return-Path'] = parseaddr(row['sender'])[1]
    message['Date'] = 'Mon, 12 Oct 2026 12:00:00 +0000'
    message['Subject'] = row['subject']
    message.set_content(row['body'])
    if row.get('html'):
        message.add_alternative(row['html'], subtype='html')
        message.set_boundary('counterexample-mime-boundary')
    return message.as_bytes()


def build_evidence(row):
    evidence = enrich(parse_email(build_raw(row), provider='gmail'),
                      {'trusted_authserv_ids': ['mx.google.com']})
    evidence['source_integrity'] = {'body_and_headers_are_untrusted_email_content': True}
    evidence['business_context'] = copy.deepcopy(row.get('business_context', {
        'verified_payment_practices': [], 'verified_relationships': [],
        'limitations': 'No organizational facts or mailbox history are assumed.',
    }))
    # No attachments are used here. Do not invent a real malware/reputation scan.
    evidence['inspection'] = {'status': 'not_run', 'findings': [], 'attachments': [], 'urls': [],
        'coverage': {'scope': 'Text-only synthetic fixture; no payload inspection performed.',
                     'network_fetch': 'disabled', 'payload_execution': 'disabled'},
        'antivirus': {'status': 'unavailable', 'scan_completed': False}}
    evidence['url_inspection'] = {'complete': False, 'results': [], 'status': 'not_configured',
                                  'remote_pages_visited': False}
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = [{'id': row['id'], 'evidence': build_evidence(row)} for row in load_inputs()]
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f'Wrote {len(result)} label-free evidence inputs. No model calls or mailbox actions.')


if __name__ == '__main__':
    main()
