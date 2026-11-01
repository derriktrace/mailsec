# Connect personal Gmail or Google Workspace

Mailsec uses the Gmail API and each mailbox owner's Google OAuth consent. A free
personal Gmail account works; a paid Workspace subscription, service account, or
Google Admin console is not required. Workspace Gmail uses the same per-account
flow, subject to the organization's application-access policies.

Start Mailsec using the [self-host guide](self-hosting.md), open its console, and
configure a decision model before authorizing an import. The Google project and
OAuth application belong to the person operating this installation. No shared
developer OAuth secret is bundled with the release.

## 1. Decide how the browser reaches Mailsec

For the default local installation, use this exact callback:

```text
http://localhost:8025/oauth/google/callback
```

When the server is on another machine, create an SSH tunnel from the device running
the browser:

```sh
ssh -N -L 8025:127.0.0.1:8025 your-user@your-server
```

Open `http://localhost:8025` on that device and keep the tunnel open throughout
Google consent. The callback then reaches the same Mailsec installation. The
background worker does not need the browser or tunnel after authorization.

If you selected a different port, use it consistently in the console URL, tunnel,
and callback. `localhost` and `127.0.0.1` are different OAuth origins; do not switch
between them halfway through consent.

For persistent remote access, configure a trusted HTTPS reverse proxy as described
in the self-host guide. An example callback is
`https://mailsec.example.com/oauth/google/callback`. Use your own domain, matching
certificate, allowed hostname, and trusted proxy configuration. The app accepts
loopback HTTP or HTTPS callbacks, not plain HTTP on a LAN address. Google applies
its own redirect validation as well. See Google's
[web-server OAuth requirements](https://developers.google.com/identity/protocols/oauth2/web-server).

## 2. Create your Google application

In the [Google Cloud console](https://console.cloud.google.com/):

1. Create or select a project. A useful display name is **Mailsec Personal Security**;
   let Google assign a unique project ID.
2. Under **APIs & Services → Library**, enable **Gmail API**.
3. Open **Google Auth Platform**. Configure the application branding with the name
   **Mailsec Personal Security**, a support email, and developer contact details.
4. Choose an **External** audience to allow personal Gmail as well as Workspace
   accounts. An Internal audience restricts eligibility to the associated Workspace
   organization and will not serve a mixed family installation.
5. For an initial External app in **Testing**, add each intended mailbox under
   **Test users**. Complete any additional fields Google requests for your selected
   application status.
6. Under **Data Access**, declare the Gmail scopes the installation will offer:
   `https://www.googleapis.com/auth/gmail.readonly` and
   `https://www.googleapis.com/auth/gmail.modify`.
7. Under **Clients**, create an OAuth client of type **Web application**, named
   **Mailsec Self-Hosted**. Add the exact callback from step 1 under **Authorized
   redirect URIs**. This is a Web client, even though the server is self-hosted.
8. Download its client JSON to a private location. It contains a client secret;
   do not commit it to Git, post it in an issue, or share it with another installation.

Google occasionally changes console labels. Its
[consent-screen guide](https://developers.google.com/workspace/guides/configure-oauth-consent)
describes branding, audience, data access, and test users.

## 3. Save Google setup in Mailsec

In **Setup → Connect Gmail**:

1. Confirm the exact callback URI.
2. Upload the downloaded Web application client JSON.
3. Enter the primary mailbox addresses to authorize, one per line. An allowlisted
   address is permission to begin setup, not access to that inbox.
4. Choose **Initial import** and save Google setup.
5. Connect each mailbox below, choosing Monitor or Manage. Sign in as its owner
   and approve the requested Google permission.

Mailsec verifies the account returned by Google matches the selected address. Use
the primary account address rather than a forwarding alias. It does not discover
or authorize every mailbox in a domain. Uploaded settings and OAuth tokens are
encrypted in the database using the installation's external encryption key. API
and worker processes pick up saved settings without a redeployment.

The supported initial windows are:

| Choice | What the initial listing includes |
| --- | --- |
| New mail | Incoming messages after the time Google setup was saved |
| Past 30 days | Incoming messages since 30 days before setup was saved; the default |
| All mail | All available incoming history, without a date cutoff |

The first two choices store a fixed epoch cutoff. Pagination and restarts do not
move the start date forward. Google supports epoch seconds in Gmail API search
queries. [Gmail filtering documentation](https://developers.google.com/workspace/gmail/api/guides/filtering).

The default release processes historical listings in batches of 250 per poll; this
is a page budget, not a 250-message total limit. The selected incoming history
includes archived mail, spam, and trash, and excludes Sent and Draft messages.
Permanent deletions cannot be recovered. Once checkpointed, incremental sync reads
new incoming messages regardless of the historical window.

Saving setup again changes the selection for new or restarted listings. It does
not rewind completed history checkpoints, delete messages, or reclassify existing
results. Reconnecting also preserves the checkpoint. Start with a small window
if you want a bounded trial; years of history take longer and can incur hosted
model charges. Historical messages use the same protection policy as new mail.

## 4. Understand permission and protection separately

| Connection access | Google permission | Mailsec behavior |
| --- | --- | --- |
| Monitor | `gmail.readonly` | Read and analyze; no Gmail label changes or sends |
| Manage | `gmail.modify` | Read plus permitted labeling, quarantine, release, and optional notification sends |

Google's modify scope also includes composing and sending mail; it is broader than
a labels-only permission. The application does not request the full-mail scope for
immediate permanent deletion. Both read-only and modify are restricted scopes.
[Google's scope descriptions](https://developers.google.com/workspace/gmail/api/auth/scopes).

Then choose the installation's protection mode:

- **Monitor / passive:** analyze and display results in the dashboard.
- **Flag:** apply `Mailsec/Review` when policy requires attention.
- **Automatic quarantine:** apply `Mailsec/Quarantine` and remove `INBOX` for
  qualifying detections. Release restores Inbox only when Mailsec removed it.

Read-only consent blocks writes even if protection mode is set to Flag or
Automatic quarantine. A Manage connection in passive mode still has a broader
Google grant, but the execution policy disables automatic changes. Local model
scores cannot authorize model-only automatic quarantine; see the
[local model guide](local-models.md).

A later completed clean or spam analysis that no longer needs review removes only
an earlier **automatic** `Mailsec/Review` label. Manual verdict labels and
corrections take precedence. The cleanup keeps other Gmail labels and the
message's Inbox, Spam, and Trash placement intact.

Quarantine leaves the original message accessible in Gmail All Mail. This is
post-delivery monitoring, not an inaccessible gateway quarantine or a guarantee
that Mailsec acts before someone opens the message.

## Consent and privacy

**Google OAuth and model data-sharing acceptance are separate permissions.**
Google consent allows Mailsec to retrieve the selected mailbox and perform only
the granted Gmail operations. It does not mean email stays on your server or
that TypeSafe sharing has been accepted. With Jev, the main assessment can send
the mailbox address and To/Cc/Bcc-derived recipient addresses when present, sender
identities, body text, complete URLs, extracted/OCR/QR content, and related context
to TypeSafe. It is not anonymized by default. The console requires a separate
explicit acceptance for synthetic setup probes, followed by an explicit tested/
saved provider and masking configuration before historical or future analysis.
Acceptance alone does not resume mail processing.
Optional recipient masking can replace known recipient-address occurrences in the
model view; it is off by default, can reduce accuracy, and is not guaranteed
anonymization. Sharing still needs explicit acceptance. See
[data sharing and consent](data-sharing.md).

Before connecting another person's mailbox, explain that the console owner can
read imported mail and its attachments. This release has one administrative token,
not separate family helper permissions. With Jev, selected email evidence goes to
TypeSafe. With a local or compatible model, it goes to the configured endpoint;
that endpoint may itself be remote. Raw mail and analysis are retained locally.
See the [architecture and data-flow description](architecture.md).

Optional quarantine notifications go to the affected mailbox. They require Manage
authorization and a separate enabled notification setting. Notifications are not
an independent trusted-helper alert service.

## Keep authorization healthy

An External Google app in **Testing** normally receives refresh tokens that expire
after seven days for Gmail access. This is appropriate for a trial, not unattended
long-term protection. Revocation, certain password changes, inactivity, token
limits, or organizational policy can also invalidate access. Mailsec can refresh
a valid grant in the background; it cannot override Google's revocation or expiry.
[Google's token expiration guidance](https://developers.google.com/identity/protocols/oauth2#expiration).

For long-term use, review Google's production verification requirements and any
applicable personal-use exception for your specific deployment. Publishing source
code does not automatically exempt a shared OAuth application from restricted-scope
verification or security-assessment requirements. A Workspace administrator may
also need to approve access according to that organization's policies.
[Google's verification guidance](https://support.google.com/cloud/answer/13463073).

Check connection health and the last successful poll in the dashboard. A revoked
grant needs reconnection; a temporary quota limit should be allowed to back off.
Locking the server screen does not revoke OAuth, but sleep, shutdown, a stopped
container runtime, or network loss interrupts processing.

## Disconnect or troubleshoot

**Disconnect** removes locally stored OAuth tokens, invalidates pending consent,
and stops subsequent requests from stale clients. An already-sent request may
finish. Imported mail, analysis history, synchronization checkpoints, and Gmail
labels remain. Disconnect does not revoke the provider grant automatically; the
owner can remove it in [Google Account connections](https://myaccount.google.com/connections).

Reconnect with Manage to enable mailbox actions, or Monitor to enforce read-only
use locally. Google may retain previously granted permissions; revoke the Google
grant first if you want to remove a former broader authorization at the provider.
Changing the Google client ID or removing a connected address from setup requires
disconnecting the affected connections first.

| Problem | Check |
| --- | --- |
| `redirect_uri_mismatch` | Exact scheme, hostname, port, path, and uploaded client's registered redirect |
| Account mismatch | Selected primary mailbox and the Google account chosen during consent |
| App access blocked | External audience/test-user membership or Workspace administrator policy |
| Callback expired / wrong browser | Keep the same browser and origin; start Connect again within ten minutes |
| Refresh failed | Testing token expiry, revoked access, changed client, or lost encryption key |
| Labels do not change | Manage consent, protection mode, action eligibility, and action ledger |

Keep the encryption key with a protected backup. Losing it prevents decryption of
saved credentials. Do not reset the database or delete imported mail to repair an
OAuth problem.
