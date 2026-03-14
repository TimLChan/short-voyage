# short-voyage

short-voyage is a command-line tool for managing cloud VPSes on [Voyager](https://cloudserver.nz).

It is designed for fast create/list/delete workflows with optional Tailscale bootstrap, perfect when running small tests or evaluating linux packages without compromising security.

## Features

- **List servers**: Display all servers in the configured Voyager project with status, hostname, and IP addresses.
- **Create servers**: Automatically create new servers with:
  - SSH key authentication
  - Randomly generated hostnames (format: `voyager-XXXXXXXX.cloudserver.nz`)
  - Pre-configured location, plan, and operating system
  - Optional features:
    - Tailscale integration (including optional exit node advertisement)
    - Fail2ban install + basic sshd jail setup
- **Delete servers**: Interactive deletion or direct deletion with `-serverid` (validated against current project server list).

## Quick Start

1. Copy the example config:

```bash
cp config.yaml.example config.yaml
```

2. Edit `config.yaml` and set:
- `voyager.api.token`
- `voyager.project.name`
- server configuration under `voyager.server`
  - the example in the config defaults to a 1 vCPU, 1GB RAM, 15GB disk server running debian 12
- Tailscale credentials only if `tailscale.enabled: true`

3. Run the command you need:

```bash
# List servers
./short-voyage -list

# Create a server (with confirmation)
./short-voyage -create

# Create a server without confirmation prompt
./short-voyage -create -force

# Delete interactively
./short-voyage -delete

# Delete directly by ID (validated against project list)
./short-voyage -delete -serverid 1234
```

## Configuration Notes

- `tailscale.enabled` controls whether Tailscale API/key generation runs.
- When `tailscale.enabled: false`, Tailscale API credentials are optional.
- When `tailscale.enabled: true`, `tailscale.api.base_url`, `tailscale.api.clientid`, `tailscale.api.clientsecret`, and `tailscale.api.tailnet` are required.
- See `tailscale.md` for required ACL/tag setup before enabling exit-node workflows.

## Command Flags
```text
Usage of short-voyage:
  -create
        Create a server
  -delete
        Delete a server
  -force
        Create server without yes/no confirmation prompt (use with -create)
  -list
        List servers in the project
  -serverid int
        Server ID to delete (used with -delete)
```

## Repository Layout

- `main.go`: CLI wiring, config load/validate, command dispatch.
- `internal/config/config.go`: config schema, YAML load, and validation.
- `internal/app/create.go`: create workflow orchestration.
- `internal/app/list.go`: list workflow.
- `internal/app/delete.go`: delete workflow.
- `internal/app/shared.go`: shared app helpers and polling utilities.
- `voyager/client.go`: Voyager API adapter.
- `tailscale/client.go`: Tailscale API adapter.

## Building from Source

You'll need [Go installed](https://go.dev/doc/install):

```bash
go build -o short-voyage
```

## Need Help?

- Review the [example config](config.yaml.example) for all options.
- Review [tailscale.md](tailscale.md) before enabling Tailscale/exit-node automation.

## License

MIT License - see [LICENSE](LICENSE) for details.
