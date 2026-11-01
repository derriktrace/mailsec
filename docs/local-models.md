# Jev, Ollama, and compatible model servers

Mailsec supports three decision providers. Choose one in **Setup → Decision model**:

| Provider | Where inference runs | Required setup |
| --- | --- | --- |
| Jev | TypeSafe's hosted API | Jev API key and a supported Jev model name |
| Ollama | The Ollama endpoint you configure | A running server with an already installed model |
| OpenAI-compatible | The endpoint you configure | Chat Completions API with JSON Schema structured output |

An OpenAI-compatible interface is a protocol option, not a requirement to buy an
OpenAI subscription or API key. The chosen server determines whether a key or
payment is required. Jev is optional. Mailsec does not download model weights,
install a model server, or silently fall back from a local endpoint to a paid API.
The single Mailsec container includes its database and scanners. Optional local
inference runs in a server you supply outside that container; no second Mailsec
container is needed when using the hosted Jev provider.

## Review and accept the data destination

The console first requires explicit acceptance of the data-sharing disclosure for
the chosen provider and destination. That allows synthetic setup probes only.
Choose the masking setting, then explicitly test/save the provider configuration
to enable mail analysis and question comparisons.
Entering a key, choosing an endpoint, or upgrading an existing installation does
not grant acceptance automatically. Jev sends selected email evidence to
**TypeSafe, a third party**, including mailbox/recipient identities, sender/body
text, complete URLs and extracted/OCR/QR content when present; it is not
anonymized by default. A compatible server receives the same evidence and may
itself be a remote or cloud service.

Optional recipient masking is off by default and affects the model view only.
It can remove known recipient-address context and reduce detection accuracy;
it does not remove all personal data or guarantee anonymity. It is available
without making a remote endpoint local, and acceptance remains required.

A synthetic setup probe still requires acceptance; it does not use mailbox mail.
Revocation prevents later model requests, with no silent fallback, but cannot
recall already sent data. See [data sharing and consent](data-sharing.md) before
selecting a destination. Mailsec makes no guarantee about the provider's retention
or training policies. A model server is private only to the extent its actual
hosting, network, logging and onward routing are private.

## Connect Ollama

1. Install and run Ollama using its own documentation. Choose and explicitly
   install a model suitable for your hardware and capable of structured output.
2. Confirm the exact installed model identifier, for example with `ollama list`.
3. In Mailsec, select **Ollama**, enter that identifier, and provide the server's
   base URL. Do not append `/api/chat`.
4. Leave the API key empty for a local server that does not require one. Supply a
   key only if your chosen authenticated server/proxy requires it.
5. Run the walkthrough's test and save after it succeeds.

Mailsec sends a non-streaming `POST /api/chat` with the question/evidence text and
a JSON Schema in `format`. Ollama documents this structured-output capability in
its [structured outputs guide](https://docs.ollama.com/capabilities/structured-outputs)
and [chat API reference](https://docs.ollama.com/api/chat).

The adapter requests temperature zero, a 32,768-token context, and up to 4,096 output
tokens. Actual model support and memory requirements vary. The application also
bounds its request bytes and splits large evidence into auditable sections. These
limits do not certify that every model handles every language or tokenizer equally
well. Test realistic mail and verify server context behavior before relying on it.

No particular local model is certified to match Jev's classifications. Selecting a
larger model or valid JSON output does not establish phishing detection accuracy.

## Reach a host model from a container

Inside the Mailsec application container, `localhost` means that container. It does
not mean the host running Ollama.

| Runtime / location | Example base URL |
| --- | --- |
| Ollama on a Docker host | `http://host.docker.internal:11434` |
| Ollama on a Podman host | `http://host.containers.internal:11434` |
| Authenticated inference service on another machine | Its private HTTPS base URL |

The release Compose configuration supplies Docker's host-gateway mapping.
Podman's internal hostnames depend on its networking configuration; see
[Podman's host-entry documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html).
Hostname resolution alone does not make a loopback-bound server reachable.

Ollama normally listens on host loopback. Arrange a restricted bind address or a
proxy reachable from the application container, and restrict its firewall access
to the intended host/container network. Do not solve connectivity by exposing an
unauthenticated model server to every LAN device or the Internet. The installer
does not change inference-server binding or host firewall rules. Ollama documents
its `OLLAMA_HOST` setting in the [server FAQ](https://docs.ollama.com/faq).

The console browser does not contact the model directly; the Mailsec server does.
A working request from your laptop therefore does not prove the application
container can connect. Use the walkthrough's test to check the actual server path.

## Connect an OpenAI-compatible server

Select **OpenAI-compatible** and enter the exact served model name and the server's
documented base URL, commonly ending in `/v1`. Do not append `/chat/completions`.
For example, a server on the Docker host might use
`http://host.docker.internal:1234/v1`; use the actual port your server listens on.

Mailsec requires:

- Non-streaming `POST <base>/chat/completions`.
- `response_format` with `type: json_schema` and strict schema support.
- A completed response containing JSON text in `choices[0].message.content`.
- A successful `finish_reason` of `stop`; refusal or length-limited output is rejected.

An endpoint that only implements basic chat or JSON-object mode is not sufficient.
Support varies by server, model, and serving configuration. For one implementation,
see [vLLM's structured-output documentation](https://docs.vllm.ai/en/latest/features/structured_outputs/).

Internet model endpoints require HTTPS. Plain HTTP is accepted only when every
resolved address is private or loopback, for an intentionally local model server.
Use HTTPS and authenticated access across any network you do not fully trust.
Credentials belong in the wizard's API-key field, not the URL. The URL validator
rejects embedded credentials, query strings, fragments, invalid ports, and explicit
metadata/link-local destinations. Every DNS answer is checked and the connection
is pinned to an approved address while retaining the original HTTPS certificate
name. IPv6 transition tunnels, metadata aliases and redirects are rejected.
Endpoint selection remains an administrator trust
decision; this is not a general network sandbox for arbitrary server names.

## What the setup test establishes

The test submits a synthetic greeting and asks for two structured judgments:
whether it is a greeting, and whether it requests a password. No mailbox message
is needed. A successful test establishes basic connectivity, the response format,
and those simple semantics. **It is not a detection accuracy test.**

Saving settings also runs the probe. A failed probe does not overwrite the saved
provider. Provider credentials are encrypted using the installation's external
encryption key; status responses do not return them. Worker processes refresh the
saved settings before new analyses. Existing messages and analyses remain intact.

A blank key can retain an existing key for the same provider and endpoint. Switching
providers or endpoints does not silently send the previous endpoint's credential to
the new one. Saving/testing Jev invokes its API and may incur a small usage charge.

## Switch providers or adjust questions

Reopen **Setup walkthrough → Decision model** at any time. Select the new provider,
enter its model/server settings, review and explicitly accept its destination
disclosure, select masking if wanted, then test and save. Acceptance by itself
does not resume real analysis. The next analysis uses that
provider; Gmail consent, historical imports, previous analyses, and saved question
versions stay intact. A switch does not automatically replay old mail. Switching
providers or changing a server/model invalidates any earlier draft test's permission
to activate: compare the draft again using the current provider before activation.

The **Advanced → Detection questions** editor works with Jev, Ollama, and compatible
servers. It changes the shared question wording and criteria without a rebuild.
A comparison makes real model calls against both the current and saved draft
questions; with a hosted endpoint it sends the selected evidence to that endpoint
and can cost money. It never changes a mailbox or a stored message verdict.
See the [question editing guide](detection-questions.md) for testing, version history,
activation, and restoring defaults. Keep a representative independent set of mail
for evaluation: matching a few expected labels does not establish general accuracy.

## Scores and mailbox actions

Local-model probabilities and confidence values are **uncalibrated model estimates**.
They are displayed as such and cannot authorize semantic-only automatic quarantine,
even when the model prints a value of 1.0 or recommends blocking. This restriction
also applies to the additional action/authority review. Those findings can require
review; they are not independent evidence of fraud.

Independent confirmed scanner detections can still qualify for quarantine when the
operator enabled that policy and the mailbox has Manage consent. Passive mode and
read-only consent continue to block writes. The automatic policy is implemented
separately from the model's requested action.

The adapter validates complete question coverage, allowed choices, finite
probabilities, distributions, usage values, and unexpected fields. Refusals,
incomplete generation, invalid output, response-size violations, or unreachable
servers produce errors rather than clean verdicts. It does not trim a response
until it becomes valid or switch to another provider. Inspect and retry failed
analyses after addressing the server problem.

## Privacy, costs, and troubleshooting

Evidence is sent to the endpoint you select. A local server can keep inference on
your hardware; a cloud endpoint or an Ollama cloud model has a different data flow.
Review your server's logs, telemetry, retention, and cloud-routing settings.
Ollama describes a local-only setting, `OLLAMA_NO_CLOUD=1`, in its
[FAQ](https://docs.ollama.com/faq). Mailsec does not configure that server setting.

Local inference avoids hosted inference fees but uses CPU/GPU resources, RAM,
storage, and electricity. First model load can be slow. Choose an appropriate
request timeout in the wizard, between 10 and 300 seconds, and verify throughput
with a small import before scanning years of mail.

The timeout covers the entire request and response, including a slow or stalled
body. Responses must be uncompressed JSON: the adapter requests
`Accept-Encoding: identity` and rejects compressed content before decompression.
Configure a model proxy to honor that header; the response is also limited to 1 MiB.

Local inference does **not** make the entire application offline. Gmail retrieval,
OAuth refresh, and antivirus signature updates still use the network. The release
also enables bounded CVE-reference checks; when a relevant identifier is present,
that identifier can be queried against NVD. URL reputation is unconfigured in this
release. See [architecture](architecture.md) for the complete data-flow boundaries.

| Symptom | Check |
| --- | --- |
| Connection refused | Container-reachable hostname, server bind address, port, firewall |
| Model not found / HTTP 404 | Exact installed/served model and selected API type |
| HTTP 400 / structured-output error | Server's JSON Schema support and supported request options |
| Timeout | Cold model load, available memory, GPU/CPU load, chosen timeout |
| Incomplete answer | Model context/output capacity and server logs; do not accept truncated output |
| Unexpected verdicts | Review evidence, test labels independently, and evaluate the model; connectivity is not accuracy |
