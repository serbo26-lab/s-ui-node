# Independent node agent

The agent reuses S-UI's `core` in a separate process, without the panel database,
web admin or global `corePtr`. The current CLI speaks protocol v2. The panel
controller supports both old v1 agents and v2 agents. Assignment migration and
upgrade boundaries are described in [nodes-model.md](nodes-model.md).

Build from this repository, using its pinned Go version:

```sh
. ./build-tags.sh
CGO_ENABLED=0 go build -tags "$(tags_for agent)" -ldflags "$(ldflags_for agent)" -o s-ui-node ./cmd/s-ui-node
go test -tags "$(tags_for agent)" ./nodeagent ./cmd/s-ui-node
```

Run with a private persistent directory, an explicit node ID and a dedicated
management identity. The certificate must have a SAN matching the address used
by the controller; the controller certificate needs client-auth usage. Keep the
CA private key on the issuing/controller side.

```sh
./s-ui-node --node-id 1 --state /var/lib/s-ui-node \
  --listen 127.0.0.1:16443 \
  --tls-cert /run/credentials/server.pem \
  --tls-key /run/credentials/server-key.pem \
  --client-ca /run/credentials/controller-ca.pem
```

There is no insecure HTTP mode. Use TLS 1.3 with a verified controller client
certificate. Listener exposure, firewall and certificate provisioning belong to
deployment; the default control listener is loopback. The tested systemd profile
uses DynamicUser, StateDirectory, LoadCredential, NoNewPrivileges and a read-only
system filesystem. S-UI's Linux core also needs AF_NETLINK to discover interfaces.

## Management protocol v2

- `GET /v2/status`: node ID, registration epoch, independent spec/access
  revisions and digests, durable and applied access, running/error and public
  certificate metadata. This response contains no client credentials.
- `PUT /v2/spec`: structural sing-box configuration without inbound `users`.
- `PUT /v2/access`: complete client grants with absolute expiry, credentials and
  either whole-node scope (`all: true`) or exact listener `tags` for legacy nodes.
- Both payloads contain `node_id`, `epoch` and a positive `revision`. Revisions
  advance independently. A foreign identity/epoch, stale revision or changed
  payload at the same revision returns 409. Exact retries are idempotent.
- Invalid JSON returns 400; an unapplied state returns 422 with a sanitized
  message. A successful response confirms the applied revision and digest.
- `GET /v1/status` reports protocol 2. `PUT /v1/deployment` returns 409, so an old
  controller cannot replace the independent access state.

Example shape only; placeholders below are not working credentials:

```json
{
  "node_id": 1,
  "epoch": "<PINNED_AGENT_EPOCH>",
  "revision": 1,
  "config": {
    "inbounds": [{
      "type": "vless",
      "tag": "node-vless",
      "listen": "::",
      "listen_port": 14443
    }],
    "outbounds": [{"type": "direct", "tag": "direct"}]
  }
}
```

`config` is server configuration; client users arrive separately through access.
Panel clients use local `inbounds: [21]` and whole-node `nodes: [1]` independently.
`nodeinbounds` remains the exact legacy field, or an applied read-only projection
after conversion. The subscription contains client outbounds/URIs, rather than
numeric server inbound IDs.

## Runtime and recovery

Access intent is saved before runtime application. Users-only changes use hot
updates; removed users, replaced credentials and changed access generations close
old sessions. A structural change rebuilds the core. Recovery combines last-good
structure with the latest access, never its obsolete user list. If safe recovery
fails, the agent stops its own core and retains the access intent.

Each rebuilt instance has a fresh cancellable context. Stopping it cancels its
asynchronous certificate-provider jobs, so a retired ACME job cannot continue
using a closed DNS/HTTP manager. Hot user changes keep the provider context.

ACME runs on the agent with persistent private storage under `--state`, separate
from management TLS. See [nodes.md](nodes.md) for path rules, public certificate
diagnostics, subscription readiness and the limits of the renewal tests.

`state-v2.json` contains last-good structure, latest durable access and applied
access, with a checksum. Updates use a temporary 0600 file in a 0700 directory,
file fsync, atomic rename and directory fsync. Application is acknowledged only
after the applied checkpoint succeeds. Failure never restores an older ACL.

On first v2 start only, the same state directory's `last-good.json` can be
imported with exact v1 scope/credentials/expiry. An existing malformed v2 state
is an error; the agent never falls back to obsolete v1 permissions. Back up the
whole state directory and upgrade the panel before the agent. Automated
downgrade and OS-reinstall recovery for the new epoch model remain later work.

There is no heartbeat deadline that shuts down the VPN. Known absolute user
expiries are checked locally once per second. A new central revocation while the
controller is unreachable can only arrive after reconnection. Traffic accounting
is not connected to the panel's client quota in this prototype.

The v2 Linux checks include real VLESS traffic, existing-session closure,
explicit re-enable and agent-manager restart, plus injected structural/runtime/
checkpoint failures and mTLS panel integration. The new model's TUIC/Hysteria2
session lifecycle, real blocked ACME provider, full host reboot, hard power loss
and installer recovery require subsequent server acceptance. Earlier prototype
checks do not establish these properties for v2.
