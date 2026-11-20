# Whole-node assignment and versioned templates

R1 adds the data/API foundation. R2 adds agent protocol v2, independent access
delivery and explicit activation of prepared migrations. R3 adds live schema 1
templates and automatic rollout. R4 adds domain/certificate resources; R5 adds
the [node interface](nodes-interface.md). Installer integration follows separately.
Existing nodes stay in legacy assignment mode until a
controlled transition.

## Client assignments

`inbounds` still contains local inbound IDs. `nodes` contains logical Node IDs:

```json
{"inbounds": [21], "nodes": [1]}
```

- Omitted `nodes` preserves assignments; `[]` removes them.
- Invalid, duplicate, unknown IDs or nodes outside active whole-node mode reject
  the transaction.
- A whole-node assignment includes all enabled connections of that node.
- New connections are published only from confirmed applied state.
- Credentials already stored for the client are preserved; missing credentials
  for VLESS, TUIC and Hysteria2 are prepared when assigning a whole node.
- Removing/re-adding a node retains and increments its grant generation.
- Changes enqueue durable access intent. The v2 access worker runs independently
  of structural compilation and provisioning jobs.

`nodeinbounds` remains the exact legacy assignment field for legacy nodes. On
converted nodes it is a read-only applied projection, not a way to select
protocols. A matching unchanged echo can be ignored; conflicting input is
rejected. New editors should send editable `nodes` and omit `nodeinbounds`.

Clients with unresolved legacy assignments return
`node_migration_required: true`. Their local edits and ordinary disable still
work; a `nodes` write requires preparation of the legacy transition first.

## Migration API

Cookie API and token APIv2 expose the same operations:

- `GET node-migration?id=<node-id>`: read-only inventory and source digest.
- `POST node-migration`, form field `data`: JSON with `node_id`,
  `report_digest` and optional `decisions`.

A decision has `client_id` and `action`, either `assign_node` or `remove`.
Complete existing selections can be prepared automatically; partial selections,
including unselected disabled connections, require an explicit decision.

Preparation writes pending grants and a migration record, and sets the node to
`prepared`. Existing exact bindings and live snapshots remain authoritative.
A changed source digest rejects stale preparation, and retrying the same
preparation is idempotent.

R2 adds `POST node-migration-activate` with the same form field and `node_id` /
`report_digest`. It requires a prepared migration, a pinned v2 agent and a fresh
source report. Missing protocol credentials are generated without replacing
existing values. The durable `activating` state becomes `node` only after the
current access snapshot is acknowledged by a running agent. Network failures
leave activation pending for the access worker to retry. Preparation by itself
never activates grants, and a v1 agent cannot activate them.

## Agent protocol v2

Control uses the existing mTLS transport, optionally over the managed SSH
connection. The following endpoints are agent endpoints, not public panel API:

- `GET /v2/status`: identity, registration epoch, structural revision/digest,
  durable access revision/digest, applied access revision/digest, running/error
  and certificate observations; no client credentials.
- `PUT /v2/access`: a complete client access snapshot, independent of a template
  or structural config. The agent persists intent before runtime application.
- `PUT /v2/spec`: a structural config without `users`. The agent combines it
  with its latest durable access, including during structural recovery.

Revisions are independent and monotonic inside a pinned epoch. A retry with the
same revision and digest is idempotent; stale revisions, different payloads at
the same revision and an unexpected epoch are rejected. An agent with access
newer than a restored panel database is not overwritten automatically. These
conflicts require explicit recovery; deleting the epoch to force acceptance is
not a recovery procedure.

Access updates can interrupt a blocked structural startup. A failed hot update
rebuilds last-good structure with current permissions. If that cannot start,
the agent stops its own core and retains the durable access intent. Reboot
restoration applies current access and known absolute expiry before serving.
Loss of panel connectivity has no three-minute shutdown timer.

Subscriptions compose confirmed applied structure with confirmed applied access
and current client permissions. Pending grants and credentials are withheld.
A confirmed stopped core is hidden until running is confirmed again; a control
timeout does not undo the last known stop.

### Upgrade boundary

Upgrade the panel controller before an agent. The new controller still handles
v1 nodes; the new agent rejects old `/v1/deployment` writers. At first start,
v2 imports `last-good.json` from the same state directory with exact listener
scope, credentials and expiry. It writes `state-v2.json`; once that file exists,
corruption is an error and never triggers fallback to the old v1 ACL.

Back up the complete agent state directory, including `state-v2.json` and
certificate files. Replacing the OS without the v2 state changes the epoch and
requires the forthcoming explicit installer recovery workflow. Automated
downgrade, new-model OS recovery and IP handover are not implemented by R2.
Do not downgrade to the old agent against an obsolete `last-good.json`.

## Template versions

`api/save` with object `nodetemplates` retains its legacy format. Saves now keep
append-only snapshots, including the original state before the first edit.

For schema 1, submit `name` and a `spec` object; edits also require `id` and
`expected_version`. A spec contains:

- `schema_version: 1`, `config: {}` and an `entries` array;
- each entry's persistent `connection_key`, `name`, `protocol`, `enable`,
  `options` and optional `sources`;
- a numeric `listen_port`, or a source bound to `/listen_port`.

Protocols are limited to `vless`, `tuic` and `hysteria2`. A key's protocol cannot
change, including after the entry was removed in an intervening version.
Server keys, certificates and client users are not inline template literals.

Source kinds are `literal`, `node_parameter`, `node_generated`,
`node_certificate` and `profile`. Node parameters include `primary_domain`,
`node_address`, `node_name` and `node_id`. Generated material is keyed by the
connection and purpose, not generated during resolution. Explicit overrides
replace inherited sources; arrays are atomic. Disabled entries do not demand
runtime resources. Unknown sources and overlapping overrides are errors.

- `GET node-template-history?id=<template-id>` returns version metadata.
- `GET node-template-version?id=<template-id>&version=<version>` returns the
  schema 1 spec. Omit `version` for the latest version.
- Legacy snapshot payloads are not returned by these endpoints.

## Live template delivery

Schema 1 templates are shared by default. A private template has `scope:
"private"` and an `owner_node_id`; other nodes cannot bind it. Template copies
retain lineage and connection keys, while runtime material belongs to each node.
An origin template cannot be deleted while copies reference it.

Use `api/save` (or token APIv2) with object `nodes`, action `applytemplate`, and
`data` containing `id` and `template_id`. Live binding requires an agent v2 node
already converted to whole-node assignment. Replacing existing connections also
requires `confirm_replace: true`. Unrelated templates with colliding connection
keys require explicit mapping and are rejected by this API; matching names,
protocols or positions never establish identity. Legacy schema 0 remains a copy
workflow and does not acquire automatic rollout implicitly.

Saving a schema 1 version transactionally updates each linked node's target and
queues durable structural work. Binding a node reads the latest version inside
its transaction. Per-node `template_target_version`,
`materialized_template_version` and `applied_template_version` distinguish saved,
resolved and acknowledged state. Runtime revisions remain independent from
template versions. The old installer rejects live nodes until the new installer
workflow is integrated; it cannot overwrite them using protocol presets.

Materialization resolves node parameters and explicit overrides, allocates
stable REALITY material and optional ports, and persists it before delivery.
Generated values use the external panel state key and are bound to node/key/
purpose. TCP and UDP reservations are separate and use the installation IP, or
management hostname for manually managed nodes. Aliases of the same host and
ports occupied by unrelated services still require installer-side inspection.
Missing certificate/profile resources keep last-good; the new resource managers
are a later stage, and resource names are never treated as certificate contents.

Renaming/reordering a connection preserves its NodeInbound ID and server tag.
Removed entries become retired records; their overrides are archived, not
silently applied again when restoring history. Retired entries do not detach
into working manual listeners. Old public connections remain until a confirming
ACK; newly added ones appear only after confirmed structure/access/certificate
readiness. Restoring history keeps surviving keys/material and advances the
template version monotonically.

Structural tasks use expiring leases, bounded retries with jitter and generation
coalescing. A rejected runtime spec waits for a new target or `nodes/retry`.
Access delivery continues independently. Immutable NodeDeployment snapshots
recover a lost ACK from agent status; a late ACK records the actual applied
version without replacing the desired version or a newer observation.

Additional `api/save` actions (same cookie/token authorization as ordinary save):

- Object `nodes`, action `setoverrides`: `id`, `expected_version` equal to the
  current node `settings_version`, and an `overrides` array. This replaces the
  active override set; `[]` resets it. Each item uses `connection_key`, `path`,
  `operation: "set" | "remove"`, and `source` for set. Explicit equal values
  remain overrides. Arrays are replaced as a whole. Removed-key overrides are
  archived; reactivating one requires an explicit new override write.
- Object `nodes`, action `privatecopy` or `sharedcopy`: `id`, `name`,
  `expected_version` equal to `settings_version`. Copies source references and
  connections, then binds this node to the copy. It does not export resolved
  domains, server keys, credentials or node overrides into shared content.
- Object `nodetemplates`, action `restoreversion`: `id`, historical `version`
  and current template `expected_version`. Creates a new current version from
  schema 1 history and automatically queues linked nodes.

Direct config/inbound writes and detaching to template ID zero are rejected for
live nodes; use overrides or a private copy. Changes to node name/address/enable
still work through ordinary save and queue structural work.

## Persistence

The shared database backup registry includes whole-node grants, template
versions, explicit overrides, encrypted generated-material storage, durable
tasks, immutable deployments, port reservations, access snapshots and migration records. Access payloads contain client
credentials and are excluded from ordinary bundle JSON. Installation secrets
still require the external panel state key; a database download alone is not a
full recovery. Deleting a disabled, confirmed-revoked node removes its grants
and control state; an unfinished installation or old-host retirement blocks
deletion.
