# IP control

IP control is optional and disabled by default. It covers authenticated clients
on local inbounds and assigned nodes, including panels with no nodes.

Open its icon after the filter on the Clients page. Set group limits there;
an individual IP limit is available above Remark in the client editor.

- An empty individual value inherits the client's group rule. Zero is unlimited.
- Group names match exactly. Removing the last client from a group does not
  remove its saved rule. Renaming a group does not move a rule to another name.
- One source address used across several inbounds or nodes occupies one slot.
  IPv4 addresses are counted individually; IPv4-mapped IPv6 is normalized;
  IPv6 addresses are grouped by /64.
- Active IPs is read-only. An unavailable count is shown as unknown, not zero.
  The count can exceed the limit during a transition.

## Admission

The default activity window is 60 seconds and the transition window is 120
seconds. Useful traffic in either direction refreshes activity. An idle tunnel
does not retain a slot indefinitely and is checked again when traffic resumes.
Transport keepalive alone does not prove excess use.

An extra address starts a bounded transition. Changing or retrying that address
does not restart the transition. Restriction requires fresh, complete evidence
and a final confirmation period. Existing active addresses are retained first.
Only the excess address's useful streams are refused or terminated. The client
is not disabled. A refused address can reconnect when a slot becomes free.

Incomplete or stale observations suspend IP restrictions for the affected
client. Nodes do not make independent decisions while the panel is unavailable;
previous decisions expire within 15 seconds. Enable, traffic quota and expiry
continue to apply independently.

Observation storage is bounded per source and per client. One client can use
at most a quarter of a source's entry budget. Overflow or an unverified source
makes that client's coverage incomplete for the activity window, including
short connections that close before the next report. It does not discard
unrelated clients' observations.

The node's ordinary status advertises `ip_control_version`. An unsupported or
unreachable node produces incomplete coverage for its assigned clients.

Established flows keep their client identity when a login is reassigned.
Ambiguous live logins suspend restrictions for the affected accounts until the
older flows close.

Client-managed HTTP, mixed, SOCKS and Naive inbounds remain authenticated when
the last enabled client is removed, including when IP control is off. Standalone
core configurations retain their native anonymous mode.

## HTTP source addresses

Direct connections use the network peer. Client-supplied forwarding headers do
not change that address. This also applies to HTTP and mixed forward proxies.

For HTTP server transports behind a reverse proxy, configure its network in
Trusted HTTP proxies (CIDR). This applies to HTTP, WebSocket, HTTPUpgrade, gRPC
and Naive server transports. The setting is delivered to nodes as well as the
local server. Use only networks belonging to proxies you control or trust.

The source is taken from X-Forwarded-For, walking from the physical peer towards
the first untrusted hop. The proxy must append the actual peer or replace the
header with a verified client address. X-Real-IP and other vendor-specific
headers are not trusted implicitly. Missing or malformed evidence from a trusted
proxy makes that client's observations incomplete; a shared proxy address is
not counted as a verified client address. Catch-all trusted networks are rejected.
Changing the trust policy clears earlier source evidence and starts fresh confirmation.

## Storage and API

Settings, group rules, individual overrides and a bounded event journal are
stored in the panel's SQLite database. They use ordinary panel backup and
restore. Live addresses, observations and admission leases are memory-only;
restoring a backup starts a new control session.

Authenticated API routes, relative to the panel's configured base path:

| Method | Route | Content |
| --- | --- | --- |
| GET | `/api/antiabuse/settings` | Settings and revision |
| POST | `/api/antiabuse/settings` | Save settings with revision checking |
| GET | `/api/antiabuse/groups` | Existing client groups and saved group rules |
| GET | `/api/antiabuse/clients?ids=1` | Read-only count, effective limit, source and freshness |
| GET | `/api/antiabuse/events` | Recent configuration and admission events |

The client save API carries `ip_control: {"limit": null}` for inheritance or a
non-negative integer for an override. Omitting the extension preserves the
existing setting. Client status includes the control scope, requested and
applied revisions, availability and update time. Consumers must check these
fields rather than treating an old count as a current decision.
