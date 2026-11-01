# Move an earlier installation into a fresh volume

This procedure supports an existing Mailsec self-host installation with either a
separate PostgreSQL 18 container or the earlier bundled single-container layout. It transfers its database and original authorization
keys to a new, isolated single-container installation. It is not the normal backup
archive restore command; see [self-hosting](self-hosting.md) for that procedure.

The helper never stops the source, enables a target worker, changes Gmail, or
performs cutover. A restored Gmail authorization must not run in two installations
at once. Keep the target in **database-only maintenance mode** until a controlled
cutover. A trial snapshot taken while the source processes mail is a rehearsal;
it will be older than the source by the time verification finishes.

Both databases must use PostgreSQL 18. A PostgreSQL 18 dump is not a supported
shortcut to a PostgreSQL 15 deployment. PostgreSQL does not guarantee loading
newer dump output into an older major server. See the
[PostgreSQL dump compatibility notes](https://www.postgresql.org/docs/18/app-pgdump.html).

## Earlier Debian image to the hardened Alpine image

Version 0.4.0-alpha.2 changes the base operating system and C library. Preserve the
old image, state directory and database volume. Transfer the database with this
logical dump/restore procedure into a **fresh** volume, even though both images
use PostgreSQL 18. Never start the new Alpine image against the old Debian physical
database directory. This also gives the new deployment independent runtime
credentials while retaining the original application encryption key.

## Prepare a private snapshot

Keep the previous release checkout and its Compose file for operating the source.
The new bootstrap deliberately refuses to reinterpret an older runtime directory
as a single-container installation. Do not reuse an existing project name, data
volume, or state directory for the target.

Find the source's PostgreSQL container name (or its single Mailsec container name) using your runtime. Set these local
variables to your own paths and names; none are credentials:

```sh
runtime=podman
source_postgres=old-mailsec-postgres
source_state="$HOME/private/mailsec-old"
stage="$HOME/private/.migration-mailsec-trial"
target_state="$HOME/private/mailsec-new"
target_project=mailsec-selfhost-migration
```

Use `docker` instead of `podman` when appropriate. The stage's parent directory
must already exist; the stage itself must **not** exist. From the new release:

```sh
python3 scripts/migrate_selfhost.py --runtime "$runtime" stage \
  --source-container "$source_postgres" --source-state "$source_state" \
  --output "$stage"
```

For an earlier **single-container** installation, use its Mailsec container as
`source_postgres` and add `--source-layout single-container` to the stage command:

```sh
python3 scripts/migrate_selfhost.py --runtime "$runtime" stage \
  --source-layout single-container --source-container "$source_postgres" \
  --source-state "$source_state" --output "$stage"
```

The bundled-source bridge logs in as the ordinary application database role using
a private temporary password file. Credentials are never arguments or printed
output, and the source transaction is explicitly read-only.

This reads a single exported, repeatable-read snapshot for the logical dump and
canonical row hashes/counts of every public table. It copies protected source
configuration and verifies that those files did not change during staging. No
source data is changed. A failed stage is discarded; the original stays intact.

The stage contains original messages, analysis evidence, Gmail authorization,
and encryption keys. Its directory is private, but the contents are not encrypted
as a backup package. Protect and encrypt it for off-host storage. Do not attach it
to an issue or include it in an open-source checkout. Only restore stages made
from your own trusted database; a SQL dump can contain executable database code.

## Prepare an empty target without mailbox processing

Choose an unused local port for the rehearsal. This example uses 18026:

```sh
./selfhost.sh configure --non-interactive --engine "$runtime" \
  --runtime-dir "$target_state" --project-name "$target_project" \
  --port 18026 --database-only
```

Before the first target start, copy the original application secrets into its new
private bootstrap directory. Keep the newly generated target database password
and connection string; they are independent of Gmail token encryption.

```sh
for name in token-encryption-key console-token google-oauth-client.json jev-key; do
  install -m 600 "$stage/source-state/secrets/$name" "$target_state/secrets/$name"
done
install -m 400 "$stage/source-state/organization.yaml" "$target_state/organization.yaml"
./selfhost.sh start --engine "$runtime" --runtime-dir "$target_state" --database-only
```

The new container starts PostgreSQL only. It does not launch the console, worker,
inspector, antivirus daemon, or signature updater. Wait until PostgreSQL is ready.
Find the new container's exact name with the runtime's `ps` command and set it:

```sh
target_container=new-mailsec-container
python3 scripts/migrate_selfhost.py --runtime "$runtime" restore \
  --target-container "$target_container" --stage "$stage"
```

The helper verifies the maintenance flag and supervisor's PostgreSQL-only state,
original application credentials, PostgreSQL major version, and absence of user
relations in the target. It restores transactionally without replacing existing
data, then compares every public table's row count and hash to the source snapshot.
It writes a private verification record only when all comparisons match. A failure
must leave the target isolated for diagnosis; do not enable its worker.

The database includes MIME originals, analyses, feedback, mailbox cursors, queued
jobs, leases, action/notification history, saved Google/model settings, and encrypted
account tokens. The matching external encryption key is essential. Exact encrypted
rows and the same key preserve the authorization material; they do not extend
Google token lifetime or override a revocation. Wizard-saved credentials override
environment defaults after restoration.

## Controlled cutover

The helper deliberately does not automate this last step:

1. Finish or cancel any browser OAuth flow before migration. Preserve the registered
   callback origin and the original Google client ID/secret.
2. Stop the old API and worker using their original Compose configuration so no new
   imports, settings changes, token refreshes, or mailbox actions occur. Keep the old
   database available for a **fresh** final stage. For a single-container source,
   operate it from its **old release checkout and image** in database-only mode;
   this keeps its original PostgreSQL available while stopping application work.
   Do not use the new image to operate that old physical volume.
3. Repeat the verified procedure into a new empty target volume using that final
   snapshot. Do not overwrite a populated rehearsal database or mix snapshots.
4. Confirm all table hashes/counts match. Keep the same tenant identifier (`selfhost`
   for the previous public self-host configuration), application keys, organization
   settings, and browser-visible callback origin. Changing a host port requires a
   matching tunnel/proxy and a Google-registered callback before reconnecting.
5. Only after the source worker is stopped and the target verified, explicitly
   remove database-only mode and start the target. Existing saved protection controls
   take precedence over installation defaults; inspect them before operational use.

If the target takes over the original browser-visible port, existing Google grants
normally need no new consent. The same credentials and refresh-token grants remain
subject to Google's expiry and revocation rules. The helper does not call Google
to test or refresh copied tokens during rehearsal.

Lease tokens and timestamps remain unchanged. A job interrupted by shutdown can
wait for its normal reclaim deadline instead of being silently marked complete.
An uncertain notification remains uncertain and is not automatically resent.

Keep the original stopped installation and protected snapshot until the new one
has passed account, scanner, import, analysis, and backup checks. If rolling back,
stop the new worker first. Do not run two workers against separate restored copies
of the same Gmail authorization, even in read-only monitoring mode: their histories
and cursor state would diverge.
