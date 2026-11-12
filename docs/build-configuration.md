---
title: Build Configuration
description: CMake variables and feature switches that set defaults and turn features on or off in the binary.
type: page
doc-category: informational
authors: Foundries.io, Claude:Opus-5.5
license: MIT
access: public
references:
  - https://github.com/foundriesio/lmp-device-register/blob/d8f39a6d95e20f5b64881ae014381682aa1c7aad/CMakeLists.txt
  - https://github.com/foundriesio/lmp-device-register/blob/d8f39a6d95e20f5b64881ae014381682aa1c7aad/src/options.cpp
relations:
  prev: ../README.md
  next: runtime-configuration.md
  parent: ../README.md
---

# Build Configuration

Pass build-time settings to CMake as `-DNAME=value`. Most of them become preprocessor definitions that set defaults or turn features on or off in the binary, so changing one means rebuilding.

```sh
cmake -S . -B build -DHARDWARE_ID=<machine> [other -D options]
cmake --build build
cmake --install build      # installs bin/lmp-device-register
```

## Values

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `HARDWARE_ID` | **Yes** | none, configure fails without it | Default value of `--hwid`, the hardware identifier (device type) sent to the server. Usually the Yocto Project `MACHINE` name. |
| `DEVICE_API` | No | unset | Default address of the device registration endpoint, for example `https://api.example.com/v1/devices`. Also moves `--device-api` and `--oauth-api` into the advanced options. |
| `OAUTH_API` | No | unset | Default OAuth2 base address for device authorization, for example `https://app.example.com/oauth2`. The tool appends `/authorization/device/` and `/token/`. Also moves `--device-api` and `--oauth-api` into the advanced options. |
| `SOTA_CLIENT` | No | `aktualizr-lite` | Name of the update client. It appears in help and error messages, and the tool runs `systemctl start <SOTA_CLIENT>` after registration, unless you pass `--start-daemon 0`. |
| `GIT_COMMIT` | No | `unknown` | Version string shown in `--help` output and in error messages. |

> **Note:** If you set neither `DEVICE_API` nor `OAUTH_API` at build time, the binary has no default addresses. You must then give the device API address at run time with `--device-api` or the `DEVICE_API` environment variable. Give the OAuth address with `--oauth-api` or `OAUTH_BASE`, unless you use `--api-token`. See [runtime-configuration.md](runtime-configuration.md#server-endpoints).

## Feature Switches

These are CMake `option()`s (`ON`/`OFF`, default `OFF`). meta-foundries builds leave `REQUIRE_FACTORY` off; it is only needed with the FoundriesFactory™ Platform.

| Option | Effect |
|--------|--------|
| `DOCKER_COMPOSE_APP` | Adds compose-apps support: the `--apps` and `--restorable-apps` options, and the `pacman` compose-app overrides in the registration request. |
| `PRODUCTION` | Builds the binary for production devices. It makes `--production` default to true, so the certificate request gets `businessCategory=production` unless you pass `--production 0`. The tool changes nothing else; the registration server reads that field and treats the device as a production device, which can come with different requirements than a development device. |
| `REQUIRE_FACTORY` | **FoundriesFactory only.** Adds the `--factory` option and makes the factory come from the environment or `/etc/os-release`. Without it, the factory defaults to `fio-device-register` and there is no `--factory` option. See [Factory](runtime-configuration.md#factory). |
| `DISABLE_PKCS11` | Builds without libp11 and replaces hardware key storage support with stubs. Any use of `--hsm-module` then fails. |

## Example Build

```sh
cmake -S . -B build \
      -DHARDWARE_ID=imx8mm-lpddr4-evk \
      -DDEVICE_API=https://api.example.com/v1/devices \
      -DOAUTH_API=https://app.example.com/oauth2 \
      -DDOCKER_COMPOSE_APP=ON \
      -DGIT_COMMIT=$(git rev-parse --short HEAD)
```

## Static Analysis

`clang-tidy.sh` runs `clang-tidy` on `src/main.cpp` with placeholder values for the required definitions (`HARDWARE_ID`, `DEVICE_API`, `GIT_COMMIT`).
