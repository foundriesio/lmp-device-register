---
title: Device Files
description: Files the tool reads from and writes to the device, and how it uses a Hardware Security Module (HSM).
type: page
doc-category: informational
authors: Foundries.io, Claude:Opus-5.5
license: MIT
access: public
references:
  - https://github.com/foundriesio/lmp-device-register/blob/d8f39a6d95e20f5b64881ae014381682aa1c7aad/src/main.cpp
  - https://github.com/foundriesio/lmp-device-register/blob/d8f39a6d95e20f5b64881ae014381682aa1c7aad/src/openssl.cpp
  - https://github.com/foundriesio/lmp-device-register/blob/d8f39a6d95e20f5b64881ae014381682aa1c7aad/src/pkcs11.cpp
relations:
  prev: runtime-configuration.md
  parent: ../README.md
---

# Device Files

This page lists what `lmp-device-register` reads from and writes to the device. In the paths below, `<sota-dir>` is the Software Over The Air (SOTA) directory set with `--sota-dir`, `/var/sota` by default.

## Files Read

| Path | Purpose |
|------|---------|
| `/etc/os-release` | Default factory (`LMP_FACTORY`) and tag (`LMP_FACTORY_TAG`). See [runtime-configuration.md](runtime-configuration.md#etcos-release-keys). |
| `/var/lock/aklite.lock` | If another process holds this lock, the update client is running and registration stops. |
| `<sota-dir>/reset-apps` | If it exists, the image comes preloaded with Restorable Apps (`DOCKER_COMPOSE_APP` builds only). |

## Checks Before Registration

1. `<sota-dir>` must be writable. The tool tests this by creating and removing `<sota-dir>/.tmp`.
2. The update client must not be running (see the lock file above).
3. `<sota-dir>/sql.db` and `<sota-dir>/client.pem` must not exist. If either one does, the device counts as already registered. Pass `--force 1` to delete them and continue.

## Files Written to the SOTA Directory

| File | Content |
|------|---------|
| `pkey.pem` | The device private key (EC prime256v1). Written only when the key is not in a Hardware Security Module (HSM). |
| `sota.toml` | Update client configuration from the server response. In HSM mode, the tool adds a `[p11]` section with the module path, the user PIN, and the key and certificate IDs. |
| `client.pem`, others | The tool writes every other file in the server response as-is. It writes each one to `<name>.tmp` first, flushes it to disk, and then renames it. |

If registration fails or is interrupted (`SIGINT`, `SIGSEGV`), the tool deletes `sql.db` and `client.pem` and cleans up the HSM token.

## Registration Request

The JSON body sent to the device API contains:

| Field | Source |
|-------|--------|
| `name` | `--name`, defaults to the device ID |
| `uuid` | Universally Unique Identifier (UUID) from `--uuid`, the HSM, or generated at random |
| `hardware-id` | `--hwid` / `HARDWARE_ID` |
| `csr` | Generated Certificate Signing Request (CSR). Subject: `CN=<uuid>`, `OU=<factory>`, and `businessCategory=production` when production. |
| `sota-config-dir` | `--sota-dir` |
| `use-ostree-server` | `--use-ostree-server` |
| `group` | `--device-group`, if given |
| `overrides.pacman.tags` | `--tag` |
| `overrides.pacman.*` (compose apps) | `--apps`, `--restorable-apps`, and `compose_apps_root` / `reset_apps_root` under `<sota-dir>` |
| `overrides.tls.*`, `overrides.storage.*`, `overrides.import.*` | Set in HSM mode, so the client loads the key and certificate from the HSM |

## HSM Storage

The tool talks to the HSM through Public Key Cryptography Standards (PKCS) #11. When you pass `--hsm-module`:

- The tool uses the token labeled `aktualizr`. If there is no such token, it initializes the first uninitialized token with that label, the SO PIN, and the user PIN.
- The tool creates the private key in the token with label `tls` and ID `01`, and stores the certificate with label `client` and ID `03`.
- If a key or certificate with those labels already exists, registration stops unless you pass `--force 1`, in which case the tool deletes them.
