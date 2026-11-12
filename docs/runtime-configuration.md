---
title: Runtime Configuration
description: Command-line options, environment variables, and /etc/os-release keys, and their order of precedence.
type: page
doc-category: informational
authors: Foundries.io, Claude:Opus-5.5
license: MIT
access: public
references:
  - https://github.com/foundriesio/lmp-device-register/blob/d8f39a6d95e20f5b64881ae014381682aa1c7aad/src/options.cpp
  - https://github.com/foundriesio/lmp-device-register/blob/d8f39a6d95e20f5b64881ae014381682aa1c7aad/src/main.cpp
relations:
  prev: build-configuration.md
  next: device-files.md
  parent: ../README.md
---

# Runtime Configuration

At run time, `lmp-device-register` takes settings from three places:

- command-line options
- environment variables
- `/etc/os-release`

Most values come from only one of these places. The ones that can come from more than one are listed with their order of precedence, highest first.

In this page, an address is a Uniform Resource Locator (URL), and the device ID is a Universally Unique Identifier (UUID).

## Environment Variables

| Variable | Effect |
|----------|--------|
| `DEVICE_FACTORY` | Factory name, used with FoundriesFactory. In meta-foundries builds, the default is `fio-device-register`. See [Factory](#factory). |
| `DEVICE_API` | Device registration endpoint address. **Overrides `--device-api`** and the build-time default. |
| `OAUTH_BASE` | OAuth2 base address. **Overrides `--oauth-api`** and the build-time default. |
| `PRODUCTION` | If set to **any value, even an empty one**, the tool registers the device as a production device. This overrides `--production 0`. Unset the variable to turn it off. |

## `/etc/os-release` Keys

The tool parses the file as key-value pairs and removes double quotes from values. If the file or a key is missing, the tool prints a message and uses the next source.

| Key | Used for |
|-----|----------|
| `LMP_FACTORY` | **FoundriesFactory only.** Default factory. Read only in `REQUIRE_FACTORY` builds; see [Factory](#factory). |
| `LMP_FACTORY_TAG` | Default for `--tag`. |

## Required Values

### Factory

The factory name goes into the subject (`OU`) of the Certificate Signing Request (CSR) and into the OAuth scope (`<factory>:devices:create`). Registration stops with `Missing factory definition` if the factory is empty or set to `lmp`.

In meta-foundries builds (`REQUIRE_FACTORY=OFF`), the Organizational Unit (OU) is `fio-device-register` and you do not need to set it. Where the value comes from depends on the build:

| Precedence | `REQUIRE_FACTORY=OFF` (default, meta-foundries) | `REQUIRE_FACTORY=ON` (FoundriesFactory) |
|------------|----------------------|---------------------------------|
| 1 | `DEVICE_FACTORY` environment variable | `--factory` / `-f` |
| 2 | built-in `fio-device-register` | `DEVICE_FACTORY` environment variable |
| 3 | not used (`LMP_FACTORY` is ignored) | `LMP_FACTORY` in `/etc/os-release` |

### Tag

The tag tells the update client which Targets to follow. The tool writes it to `overrides.pacman.tags`. If it is empty, registration stops with `Missing tag definition`.

1. `--tag` / `-t`
2. `LMP_FACTORY_TAG` in `/etc/os-release`

### Hardware ID

1. `--hwid` / `-i`
2. `HARDWARE_ID` set at build time (always present)

### Server Endpoints

The device API address is where the tool sends the registration request; it expects HTTP 201 back. Before registering, the tool checks that this address is reachable.

1. `DEVICE_API` environment variable
2. `--device-api`
3. `DEVICE_API` set at build time

The OAuth2 base address, used only when you do **not** pass `--api-token`:

1. `OAUTH_BASE` environment variable
2. `--oauth-api`
3. `OAUTH_API` set at build time

If no OAuth address is set and no token is given, the tool stops with `No --oauth-api or --device-api set, cannot authenticate`.

## Authentication

- **API token:** pass `--api-token <token>` (`-T`). The tool sends it in the HTTP header named by `--api-token-header` (default `OSF-TOKEN`).
- **OAuth2 device flow**, used when no token is given: the tool requests a device code from `<oauth>/authorization/device/` and prints an address and a user code. It then polls `<oauth>/token/` until someone approves the device in a browser. The tool base64-encodes the token it receives and sends it as `Authorization: Bearer <token>`.

## Command-Line Options

Boolean options take an explicit value, for example `--force 1` or `--start-daemon 0`. Boost accepts `1/0`, `true/false`, `yes/no`, and `on/off`.

### Common Options (`--help`)

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --sota-dir` | `/var/sota` | Directory where the tool writes keys and configuration. |
| `-f, --factory` | see [Factory](#factory) | **FoundriesFactory only.** Factory to register with. Only in `REQUIRE_FACTORY` builds. |
| `-g, --device-group` | none | Device group to assign the device to. |
| `-n, --name` | device ID | Device name shown in the dashboard. |
| `-t, --tag` | `LMP_FACTORY_TAG` | Tag the update client follows. |
| `-T, --api-token` | none | API token. If not given, the tool uses OAuth2. |
| `--device-api` | none | Device registration address. Listed here only when neither `DEVICE_API` nor `OAUTH_API` was set at build time. |
| `--oauth-api` | none | OAuth2 base address. Listed here under the same condition. |
| `-a, --apps` | all Target apps | Comma-separated list of compose apps to enable. Only in `DOCKER_COMPOSE_APP` builds. |
| `-A, --restorable-apps` | see below | Comma-separated list of Restorable Apps. Only in `DOCKER_COMPOSE_APP` builds. |

`--restorable-apps` behavior:

- Not given: if `<sota-dir>/reset-apps` exists, the image comes preloaded with Restorable Apps. The tool turns them on, and the list matches the apps list.
- `--restorable-apps "app1,app2"`: turned on. The resulting list is the union of the compose apps and the apps given.
- `--restorable-apps ""`: turned off.

### Advanced Options (`--help-advanced`)

The `--hsm-*` options use a Hardware Security Module (HSM) through Public Key Cryptography Standards (PKCS) #11.

| Option | Default | Description |
|--------|---------|-------------|
| `-H, --api-token-header` | `OSF-TOKEN` | HTTP header that carries `--api-token`. |
| `--device-api` | build-time `DEVICE_API` | Shown here when `DEVICE_API` or `OAUTH_API` was set at build time. |
| `--oauth-api` | build-time `OAUTH_API` | Shown here under the same condition. |
| `--force` | `0` | Remove data left by an earlier registration: `sql.db`, `client.pem`, and conflicting HSM objects. |
| `-m, --hsm-module` | none | Path to the PKCS #11 `.so` module. Turns on HSM mode. |
| `-P, --hsm-pin` | none | PKCS #11 user PIN. Required with `--hsm-module`. |
| `-S, --hsm-so-pin` | none | PKCS #11 security officer PIN. Required with `--hsm-module`. |
| `-i, --hwid` | build-time `HARDWARE_ID` | Hardware identifier. |
| `-l, --mlock-all` | `1` | Lock the process memory with `mlockall()` so keys are not paged out. |
| `-p, --production` | `0` (`1` in `PRODUCTION` builds) | Add `businessCategory=production` to the CSR, so the server registers it as a production device. |
| `--start-daemon` | `1` | Run `systemctl start <SOTA_CLIENT>` after registration. |
| `--use-ostree-server` | `1` | Pull the OSTree repository through the OSTree proxy server instead of the device gateway. |
| `-u, --uuid` | see below | Device ID, used as the certificate CN. |
| `-v, --validate-uuid` | `1` | Stop if the device ID is not in the standard `8-4-4-4-12` hex format. With `0`, the tool only prints a warning. |

The device ID comes from the first of these that provides one:

1. `--uuid`
2. With `--hsm-module`: the first PKCS #11 slot whose description contains a lowercase UUID
3. A random UUID

### HSM Option Rules

- Passing `--hsm-pin` or `--hsm-so-pin` without `--hsm-module` is an error.
- `--hsm-module` requires both PINs, and the tool checks the HSM before registering.

## Examples

```sh
# Interactive OAuth registration, tag from /etc/os-release
lmp-device-register --name gateway-01

# Non-interactive, with an API token, into a group, without starting the client
lmp-device-register -T "$TOKEN" -n gateway-01 -g field-units --start-daemon 0

# Point at a different server for one run
DEVICE_API=https://staging.example.com/v1/devices \
OAUTH_BASE=https://staging.example.com/oauth2 \
lmp-device-register -n test-device

# Register using an HSM
lmp-device-register -m /usr/lib/softhsm/libsofthsm2.so -P 87654321 -S 12345678

# Re-register a device that was registered before
lmp-device-register -n gateway-01 --force 1
```
