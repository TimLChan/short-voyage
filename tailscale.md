## tailscale configuration

When using the tailscale feature in short-voyage, additional configuration is required in Tailscale to ensure that the exit node is properly set up and ready for use.

### Create a new tag and Exit Node ACLs

Log into your tailscale dashboard and navigate to the [Access controls](https://login.tailscale.com/admin/acls/file) section.

In the visual editor, make the follwing changes:

- Under `Tags`, create a new tag called `voyager` with the tag owner as `autogroup:member`
- Under `Auto Approvers` add the previously created tag in the `Exit nodes` section

If editing the JSON file directly, the file should have the following sections inside

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

### Create a Tailscale OAuth Client

Navigate to the [Trust Credentials](https://login.tailscale.com/admin/settings/trust-credentials) section and create a new OAuth client.

The client should have the `auth_keys` scope with both read and write permissions. When asked for `Tags`, use the `voyager` tag created previously.

Save the client ID and client secret for later use.

### Update the configuration file with Tailscale credentials

Update the `config.yaml` file with your Tailscale credentials

- `clientid`: The client ID of your Tailscale OAuth client
- `clientsecret`: The client secret of your Tailscale OAuth client
- `tailnet`: The name of your Tailscale tailnet found in the [General](https://login.tailscale.com/admin/settings/general) section
