---
title: Config
description: Configuration system
weight: 1
---

## Overview

xodbox behaviour is driven by `xodbox.yaml`. The config file has four
top-level sections:

| Section     | Type                   | Purpose                                  |
|-------------|------------------------|------------------------------------------|
| `defaults`  | `map[string]string`    | Global defaults shared across components (e.g. `server_name`, `default_ip`). |
| `handlers`  | `[]map[string]string`  | Protocol listeners to start. Each entry must have a `handler` key naming a registered type. |
| `notifiers` | `[]map[string]string`  | Event sinks. Each entry must have a `notifier` key naming a registered type. |
| `workers`   | `[]map[string]string`  | Background tasks. Each entry must have a `worker` key naming a registered type. |

Generate a starter config with:

```sh
xodbox config init
```

## Managing config

### Web UI

Admin users can view and edit the config from the **Config** page in the
admin web UI. The structured editor shows each section with add/remove
controls; a raw YAML tab is also available for power users. After saving,
restart xodbox for changes to take effect.

### CLI

```sh
xodbox config                        # print the loaded config
xodbox config init                   # write the default config to disk
xodbox config validate               # check the config for errors
xodbox config get defaults.server_name   # read a value by dot-path
xodbox config set defaults.server_name foo   # write a value by dot-path
```

The `set` subcommand validates before writing; invalid configs are
rejected.

## Validation

`ValidateConfigFile` checks that every handler, notifier, and worker
entry references a registered type name. Unknown names and missing type
keys are reported as errors.

## Changes require restart

Config is loaded once at startup. Handlers bind network ports, so
hot-reload is impractical. After editing the config (via UI, CLI, or
direct file edit), restart the xodbox process for changes to take effect.
