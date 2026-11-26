# Nodes integration (legacy schema 0)

The primary whole-node/live-template workflow is documented in
[nodes-model.md](nodes-model.md), [nodes-interface.md](nodes-interface.md),
[node-installer.md](node-installer.md) and [the quickstart](nodes-quickstart.md).
The copy-template and exact inbound-assignment behavior below applies to the
legacy path, not live schema 1 templates or installer model 2.

The local `inbounds` table and local core are unchanged in meaning. Remote
inbounds live in `node_inbounds` and are executed only by the separate agent.
A client uses two independent numeric arrays:

```json
{"inbounds": [21], "nodeinbounds": [1]}
```

The same integer may appear in both arrays. IDs are table identities; tags are
labels. The exact wire name is lowercase `nodeinbounds`. Omitting it during an
old client edit preserves remote assignments. An explicit `[]` clears only
remote assignments. Null, duplicate/zero/non-numeric IDs and unknown remote IDs
are rejected in the client transaction. Bulk create/edit/delete use the same
rules. Client names/subscription URLs and existing protocol credentials remain
unchanged when assigning a node.

## Administration API

The existing authenticated cookie API and token API both expose:

- `GET api/nodes` or `GET apiv2/nodes`: `obj.nodes`, `obj.nodetemplates`,
  `obj.nodeinbounds`.
- `POST .../save`, form fields `object`, `action`, `data` (JSON): objects
  `nodes`, `nodetemplates`, `nodeinbounds`; actions `new`, `edit`, `del`.
  Nodes also support `applytemplate` (`id`, `template_id`) and `retry` (`id`).
- `GET .../node-links?id=<CLIENT_ID>`: read-only confirmed remote links
  (`remark`, `uri`) for the client and QR dialogs; not stored in `Client.Links`.
- Use the existing `clients` save action to set `nodeinbounds`. Read a client's
  complete protocol configuration with `clients?id=<ID>`; the unfiltered list
  intentionally omits that large field, as before.

Nodes saves use their own service and do not call the local ConfigService or
local core. New remote records receive IDs from their own SQLite tables.

A node's writable fields are `name`, `enable`, `address` (management HTTPS URL),
`linkaddress` (VPN hostname/IP, without scheme or port), `template_id`, `config`
(this node's base sing-box configuration), and write-only:

```json
{"control_tls":{"ca":"<CA PEM>","certificate":"<CONTROLLER CERT PEM>","key":"<CONTROLLER PRIVATE KEY PEM>"}}
```

Omit `control_tls` to retain the saved identity. It never comes back in the
ordinary node JSON. Use a different controller/server trust identity per node
when provisioning. The agent's configured node ID must match the panel record;
TLS 1.3 verifies its SAN and requires a controller client certificate. Redirects
are refused. Default agent control listens on loopback; use a verified private
management route or a secured tunnel. Provisioning that route is currently a
manual deployment operation.

Node inbounds have `node_id`, `tag`, `type`, `enable`, `options` (server protocol
options) and `client_tls` (public client TLS options). Supported types are
VLESS/TUIC/Hysteria2. Real traffic has been checked for all three with strict
TLS. The original automated standalone Windows sing-box probe timed out;
the Linux probe passed. On 2026-11-12 the user reported successful TUIC tests
in three networks, including the development network. A general Windows/network
restriction is not established. The automated timeout's cause remains unknown;
the user's client engine/version was not reported.
Users/type/runtime tag are owned by the compiler. Inbound IDs remain fixed when
editing; moving one to another node requires creating a new record. Tags may
repeat on different nodes. An existing inbound cannot change protocol in place.

## Templates and per-node settings

A template has `name`, base `config` and `blueprints`. Each blueprint has a
stable `key`, `tag`, `type`, `enable`, server `options` and public `client_tls`.
Applying it creates separate node-inbound IDs for each node. Reapplying uses a
three-way merge of the previous defaults, the current node settings and the new
defaults: individual ports, TLS keys and other overrides survive. Arrays and
scalar values are merged as whole values. A stable blueprint key cannot change
protocol. Removing a blueprint leaves its existing node inbound as a manual
record, retaining its ID and client bindings.

Changing a template does not silently redeploy all its nodes. Use explicit
`applytemplate` or select a different template when editing a node. Re-selecting
the same template during an ordinary node edit does not reapply it. Template ID
zero detaches the template while keeping the materialized node configuration.
Legacy base-only records are adopted without discarding individual settings.

`{{NODE_ADDRESS}}`, `{{NODE_NAME}}` and `{{NODE_ID}}` are resolved for each node
when compiling config, inbound options and public TLS options. The stored
template keeps its placeholders. Template baselines and source bookkeeping
cannot be overwritten through ordinary inbound JSON edits.

## Configuration and subscription flow

1. A committed client binding identifies a remote inbound, not a cached URI or
   an External Link.
2. The node compiler selects enabled assigned clients and their existing
   protocol credentials. It builds stable server tags and private user names.
   Absolute expiries travel as access metadata for independent local checks.
3. A private desired snapshot/revision is persisted before management network
   I/O, including during an outage. The controller reads agent status, continues
   above its existing revision if necessary, and retries the complete deployment.
4. Only a verified response matching revision/digest/running state advances the
   applied snapshot. Network or configuration failures retain the applied one.
5. The old subscription URL dynamically combines existing local/external links
   and transient adapters from confirmed remote snapshots. The existing URI,
   sing-box and Clash generators are reused. No remote adapter is written into
   local `inbounds`, TLS, routing or External Link tables.

REALITY public keys are derived from the server private key. Server-only key
material and filesystem paths are not published. Client TLS options carrying
private server key fields are refused. Providers issue/renew on the agent using
sing-box's existing implementation. Remote certificate file contents are not
fetched onto the panel automatically; provide client trust explicitly when
using a private CA.

`pending`, `desired_revision`, `applied_revision`, `last_seen` and `last_error` distinguish
pending application from confirmed state. Error codes identify compilation,
control TLS/address, connection/status, deployment rejection or acknowledgement
failure without echoing secret-bearing parser errors. Agent details remain in
its protected `last-error.json`.

A rejected revision (HTTP 422) is not repeatedly applied while the agent still
runs its last-good configuration. Change the settings or use explicit `retry`
to allocate a fresh revision. Connection failures continue to be retried.

## Access and recovery

Remote user bytes increment the same client counters as local inbounds.
Client.Enable remains global: manual disable, expiry and the quota deplete task
remove node users. Known expiry is enforced by the agent without the panel.
New central revocation during an outage is delivered after reconnection.

Open acceptance gap: a simultaneously invalid structural configuration can
also block delivery of a new access change, since deployment is currently one
complete snapshot and rollback restores the previous users too. This follows
from the implementation and has not yet had a dedicated live test. Independent
access revocation under a rejected structural change remains a release gate.

An internal persisted access generation distinguishes quick disable/re-enable,
credential and assignment changes even between polls. It changes the agent's
private session identity, not the user's UUID/password/URL, so old sessions are
closed when the new generation arrives. Subscriptions do not publish a new
generation before acknowledgement. Current client disable, expiry or assignment
removal hides remote endpoints immediately in newly fetched subscriptions.

The controller runs after database commit, has bounded network concurrency and
does not hold a SQLite write transaction during management requests. It is a
durable desired-state reconciliation loop, not a completed installer/job-history
system. It may combine intermediate configuration edits; access generations
preserve the need to revoke prior sessions. Multi-panel concurrent control of
one agent is not supported.

Deletion of a node requires confirmed disable/revocation first. Agent last-good
state remains available through controller outages and agent/host restarts.
See [node-agent.md](node-agent.md) for the runtime protocol and durability limits.

## Domain, TLS and deployment boundaries

`linkaddress` changes the address in subscriptions. It does not create DNS,
obtain a certificate, configure nginx, open firewall ports, or install a site.
Management TLS and VPN TLS are different identities. The node/template editor
reuses the certificate-provider editor with this node's HTTP-client tags, not
the panel's providers, HTTP clients or operating-system restrictions. ACME and
Cloudflare Origin CA formats are supported; Tailscale providers are not enabled
for nodes in this build profile. Only ACME has completed the live provider test.

Provider `data_directory` is relative to private certificate storage inside
agent `--state`. Empty selects a stable separate namespace per type and tag.
Absolute/escaping/overlapping directories and symlink descendants are refused.
Relative server cert/key paths resolve against node state; absolute paths refer
to the node, never the panel. Provider secrets remain in private node config and
backups; they are not subscription fields.

`tls_status` reports observation revision/time and public certificate metadata
per inbound: provider, server name, state, validity and SHA256. This is storage/
config inspection, not an external handshake or proof of client trust. A
provider endpoint is not published until the matching applied revision has a
ready, unexpired report. Expired endpoints are omitted from new subscriptions
even with an earlier observation timestamp. Downloaded profiles rely on their
own TLS verification.

The builtin provider performs issuance, retry and automatic renewal. A test CA
with 120-second certificates exercised renewal after provider restart inside
its renewal window, failure with the previous valid certificate, actual expiry,
and return to public CA trust. This is not a long-term timer test. `nodes/retry`
retries deployment, not forced certificate renewal. Full per-provider job/error
history and manual force-renew are not implemented; details remain in protected
agent logs.

SSH installation, updating/rollback, and two-remote-node acceptance remain
later stages. DNS/challenge routing and firewall policy still need review for
the chosen deployment.

The Nodes screen manages nodes, templates and node inbounds, with confirmed,
pending, offline and error states. Narrow screens use lists with visible actions.
Single and bulk client dialogs offer a separate Nodes Inbound Tag. Client and QR
dialogs show confirmed remote links as read-only generated values. The existing
protocol forms and TLS editor are reused with an explicit node context, without
writing to the panel's local TLS table. The certificate lifecycle and its
current testing limits are described above.
