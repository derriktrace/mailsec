"""Optional reputation never submits known private or ambiguous link hosts."""

from types import SimpleNamespace

import httpx
import pytest

from mailsec.reputation import ReputationClient, canonical_url


@pytest.mark.parametrize('host', [
    '127.1', '127.0.0.1.', 'localhost.', '0177.0.0.1', '0x7f.0.0.1',
    '2130706433', '0x7f000001', '010.0.0.1', '192.168.1.1.', 'service.local.',
    'service.internal.', 'router.home.arpa.', 'printer.localdomain.', '０１７７.０.０.１',
    '[::ffff:127.0.0.1]', '[64:ff9b::7f00:1]', '[2002:7f00:1::]',
    '[2606:4700:4700::1111%25eth0]',
    '999.999.999.999', '08.0.0.1', 'bad_host.example.com',
])
def test_private_numeric_and_internal_urls_are_never_submitted(host):
    value = f'http://{host}/account?private=do-not-submit#secret'
    with pytest.raises(ValueError):
        canonical_url(value)
    settings = SimpleNamespace(organization={}, web_risk_api_key='synthetic')
    client = ReputationClient(settings, None, transport=httpx.MockTransport(
        lambda request: pytest.fail('A private destination was submitted externally')))
    result = client.check(value)
    assert result['status'] == 'unknown'
    assert 'not submitted' in result['reason']
    assert 'url' not in result


def test_public_url_normalization_preserves_path_query_and_fragment():
    assert canonical_url('https://Example.COM.:443/a%2Fb?token=opaque#section') == (
        'https://example.com/a%2Fb?token=opaque#section')
    assert canonical_url('https://8.8.8.8:443/path') == 'https://8.8.8.8/path'
