# Node maintenance

## Control certificates

For nodes managed by the SSH installer (model 2), the panel checks the control
CA, controller certificate and agent certificate every minute. It starts renewal
when any identity has less than 30 days remaining or fails validation. Failed
attempts are retried at most once per hour. Unfinished jobs resume after a panel
restart using their encrypted installation plan.

Renewal uses the saved dedicated SSH key and pinned server host key. It follows
the normal agent update procedure, including a brief service restart. Node and
inbound identities, protocol keys, client credentials and subscription URLs are
preserved. The agent waits for fresh authenticated client access before starting
the saved VPN configuration after installation.

Renewal does not replace a changed SSH host key or recover a reinstalled OS.
Use explicit node recovery with new SSH credentials for that case. Installation
errors appear in the node's existing job history. Manual control deployments
and legacy nodes require separate certificate maintenance.

## HTTP-01 firewall permissions

HTTP-01 requires incoming TCP port 80. The panel opens this permission through
its privileged SSH connection when UFW or firewalld is active, before requesting
a certificate. The agent does not receive firewall administration privileges.
Provider firewalls must allow the challenge traffic separately.

The HTTP-01 permission is tracked independently from VPN listener ports and
remains available for autonomous certificate renewal. Changing VPN protocols
does not remove it. The panel releases its permission when the node is disabled,
deleted or retired, or after a replacement certificate method is confirmed.
Existing administrator rules and permissions still used by other managed
listeners are retained.

## Interrupted installation

A new installation operation requires a fresh authenticated access snapshot.
While that bootstrap is pending, structural delivery waits and retries instead
of permanently rejecting the configuration. An expired worker lease can delay
this retry; the installer continues verification without recreating clients or
their credentials.
