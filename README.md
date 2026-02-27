# short-voyage

short-voyage is a simple command-line tool for managing temporary cloud servers on [Voyager](https://cloudserver.nz). Perfect for spinning up quick servers when you need them and deleting them when you're done.

## Features

- **List Servers**: Display all servers in the specified Voyager project with their status, hostname, and IP addresses
- **Create Servers**: Automatically create new servers with:
  - SSH key authentication
  - Randomly generated hostnames (format: `voyager-XXXXXXXX.cloudserver.nz`)
  - Pre-configured location, plan, and operating system
  - Optional features including:
      - Tailscale integration including running an exit node
      - Fail2ban integration
- **Delete Servers**: Interactive deletion or direct deletion with `-serverid` (validated against current project server list)

## Configuration


## Usage

```text
Usage of short-voyage:
  -create
        Create a new server with the configured settings
  -delete
        Delete a server
  -force
        Create server without yes/no confirmation prompt (used with -create)
  -list
        List all servers in the project
  -serverid int
        Server ID to delete (used with -delete)
```

## Building from Source

You'll need [Go installed](https://go.dev/doc/install):

```bash
go build -o short-voyage
```

## Need Help?

- Check the [existing README](README.md) for more technical details
- Review the [example config](config.yaml.example) for all available options

## License

MIT License - see [LICENSE](LICENSE) for details.
