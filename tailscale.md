# Tailscale Configuration

This guide is only required when `tailscale.enabled: true` in `config.yaml`.

If `tailscale.enabled: false`, short-voyage skips Tailscale authentication/key generation and this setup is not required.

## 1. Create a tag and exit-node approver rules

Log in to your Tailscale dashboard and open [Access controls](https://login.tailscale.com/admin/acls/file).

In the visual editor, make the following changes:

- Under `Tags`, create a new tag called `voyager` with the tag owner as `autogroup:member`
- Under `Auto Approvers` add the previously created tag in the `Exit nodes` section

If editing the ACL JSON directly, include sections like:

```json
// Example/default ACLs for unrestricted connections.
{
	"tagOwners": {
		"tag:voyager": ["autogroup:member"],
	},
	"autoApprovers": {
		"exitNode": ["tag:voyager"],
	},
    ...
}
```

## 2. Create a Tailscale OAuth client

Navigate to the [Trust Credentials](https://login.tailscale.com/admin/settings/trust-credentials) section and create a new OAuth client.

The client should have the `auth_keys` scope with both read and write permissions. When asked for `Tags`, use the `voyager` tag created previously.

Save the client ID and client secret for later use.

## 3. Update `config.yaml`

When Tailscale is enabled, set:

- `clientid`: The client ID of your Tailscale OAuth client
- `clientsecret`: The client secret of your Tailscale OAuth client
- `tailnet`: The name of your Tailscale tailnet found in the [General](https://login.tailscale.com/admin/settings/general) section

Example:

```yaml
tailscale:
  enabled: true
  exit_node: true
  api:
    base_url: "https://api.tailscale.com/api/v2"
    clientid: "ts-..."
    clientsecret: "ts-..."
    tailnet: "example-tailnet"
    scopes:
      - "auth_keys"
  tags:
    - "voyager"
```

To disable integration entirely:

```yaml
tailscale:
  enabled: false
```
