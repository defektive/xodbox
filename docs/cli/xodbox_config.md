---
title: Config
description: manage the xodbox config file
---

## Synopsis

View, validate, and edit the xodbox config file.

Running `xodbox config` with no subcommand prints the currently loaded
config. Use a subcommand for specific operations.

```
xodbox config [flags]
xodbox config [command]
```

## Available Commands

| Command    | Description |
|------------|-------------|
| `init`     | Write the default config file to disk |
| `validate` | Validate the config file |
| `get`      | Get a config value by dot-notation path |
| `set`      | Set a config value by dot-notation path |

## Options

```
  -e, --embedded   Print the embedded config file
  -h, --help       help for config
```

## Options inherited from parent commands

```
      --config string   Config file path (default "xodbox.yaml")
      --debug           Debug mode
      --reset-db        Reset database
```

## init

Write the embedded default config to the `--config` path (default
`xodbox.yaml`). Refuses to overwrite unless `--force` is set.

```
xodbox config init [--force]
```

## validate

Load the config file and check that all handler, notifier, and worker
names are valid. Exit code 1 on validation failure.

```
xodbox config validate
```

## get

Query a specific value from the config file using a dot-notation path.

```
xodbox config get <path>
```

Examples:

```
xodbox config get defaults.server_name
xodbox config get handlers.0.listener
xodbox config get notifiers.0.notifier
```

## set

Set a specific value in the config file and save it. The config is
validated before writing; invalid configs are rejected.

```
xodbox config set <path> <value>
```

Examples:

```
xodbox config set defaults.server_name MyServer
xodbox config set handlers.0.listener :8080
xodbox config set notifiers.0.filter "^HTTP"
```

## SEE ALSO

* [xodbox](_index.md)	 - A network interaction listening post
