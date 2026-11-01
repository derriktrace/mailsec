"""Small bounded loopback-only probes for the privileged container supervisor."""

import http.client
import json


def local_health(port, *, timeout=2):
    # HTTPConnection never consults proxy environment variables or follows a
    # redirect. Restrict ports as well: configuration cannot turn this into SSRF.
    if port not in (8025, 8080):
        raise ValueError('Unexpected local health service')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    try:
        connection.request('GET', '/health', headers={'Host': 'localhost'})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('Local service is not ready')
        raw = response.read(16385)
        if len(raw) > 16384:
            raise ValueError('Local health response exceeds its budget')
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError('Invalid local health response')
        return document
    except http.client.HTTPException as error:
        raise ValueError('Invalid local health protocol response') from error
    finally:
        connection.close()
