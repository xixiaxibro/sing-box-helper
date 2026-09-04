# sing-box-helper

A small set of macOS command-line helpers for running sing-box from a Base64
Trojan subscription. It refreshes reachable nodes, builds a local mixed proxy
on `127.0.0.1:7890`, and supports automatic or manual node selection.

## Security

Subscription URLs, generated configurations, node metadata, logs, backups,
passwords, and the sing-box binary are intentionally excluded from this
repository. Treat `subscription.url` and generated `config.json` files as
secrets. The helper writes sensitive files with mode `0600`.

## Requirements

- macOS
- Node.js 20 or newer
- sing-box
- `lsof`, `networksetup`, and standard Unix tools

## Install

```sh
install -d "$HOME/.local/bin" "$HOME/.local/lib"
install -m 755 bin/sb-* "$HOME/.local/bin/"
install -m 644 lib/sb-refresh.mjs "$HOME/.local/lib/"
install -m 755 /path/to/sing-box "$HOME/.local/bin/sing-box"
```

Add a subscription and start the proxy:

```sh
sb-refresh 'https://provider.example/subscription'
sb-up
```

The URL is stored locally at `~/.config/sing-box/subscription.url`; never
commit or share that file.

## Commands

- `sb-up` refreshes the subscription and starts sing-box.
- `SB_SKIP_REFRESH=1 sb-up` starts with the existing generated config.
- `sb-down` stops the managed process.
- `sb-status` shows the process, listener, system proxy flags, and recent log.
- `sb-update` refreshes and validates the generated config without restarting.
- `sb-nodes` lists reachable nodes.
- `sb-us` lists reachable US nodes.
- `sb-use auto` enables automatic selection.
- `sb-use <tag>` pins a node and restarts the managed process.

## Notes

The subscription decoder accepts standard and URL-safe Base64. Only
`trojan://` entries are imported. TCP reachability is used as a first-pass
filter; sing-box's `urltest` group then measures application-level reachability.
