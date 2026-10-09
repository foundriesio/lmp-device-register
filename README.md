---
title: Device Register
description: Register an embedded Linux device with a device registration server so it can receive over-the-air updates.
type: page
doc-category: informational
authors: Foundries.io, Claude:Opus-5.5
license: MIT
access: public
references:
  - https://github.com/foundriesio/lmp-device-register/tree/d8f39a6d95e20f5b64881ae014381682aa1c7aad
  - https://github.com/foundriesio/meta-foundries/tree/main/recipes-sota/fio-device-register
relations:
  next: docs/build-configuration.md
---

# Device Register

`lmp-device-register` registers an embedded Linux® device with a device registration server, so the device can receive over-the-air (OTA) updates. The [meta-foundries](https://github.com/foundriesio/meta-foundries) layer builds it as `fio-device-register`; see [Background](#background). It runs on the device and does the following:

1. Generates a key pair and a Certificate Signing Request (CSR). It creates the key with OpenSSL, or inside a Hardware Security Module (HSM) through Public Key Cryptography Standards (PKCS) #11.
2. Authenticates the user with an API token or with the OAuth2 device authorization flow. In that flow, the user opens a link in a browser and enters a code.
3. Sends the CSR and the device details to the device registration API.
4. Writes the returned certificate and update client configuration to the Software Over The Air (SOTA) directory, `/var/sota` by default.
5. Starts the update client, `aktualizr-lite` by default, unless told not to.

## Quick Start

```sh
# Build (HARDWARE_ID is mandatory)
cmake -S . -B build \
      -DHARDWARE_ID=intel-corei7-64 \
      -DDEVICE_API=https://api.example.com/v1/devices \
      -DOAUTH_API=https://app.example.com/oauth2
cmake --build build

# Run on the device (as root)
lmp-device-register --name my-device --tag main
```

Run `lmp-device-register --help` for the common options and `lmp-device-register --help-advanced` for all of them.

## Configuration at a Glance

You configure the tool at three levels. The details are in `docs/`.

| Level | Where it is set | Reference |
|-------|-----------------|-----------|
| Build time | CMake variables (`-DNAME=value`) | [docs/build-configuration.md](docs/build-configuration.md) |
| Run time | Command-line options, environment variables, `/etc/os-release` | [docs/runtime-configuration.md](docs/runtime-configuration.md) |
| On the device | Files read and written in the SOTA directory and HSM | [docs/device-files.md](docs/device-files.md) |

The values that registration needs:

| Value | Required | Where it comes from |
|-------|----------|---------------------|
| Hardware ID | Yes | `-DHARDWARE_ID` at build time, or `--hwid` |
| Factory | Yes | Built in as `fio-device-register`, or the `DEVICE_FACTORY` environment variable. FoundriesFactory builds also read `--factory` and `LMP_FACTORY` in `/etc/os-release`; see [Factory](docs/runtime-configuration.md#factory) |
| Tag | Yes | `--tag` or `LMP_FACTORY_TAG` in `/etc/os-release` |
| Device API address | Yes | `DEVICE_API` environment variable, `--device-api`, or `-DDEVICE_API` at build time |
| OAuth API address | Only without `--api-token` | `OAUTH_BASE` environment variable, `--oauth-api`, or `-DOAUTH_API` at build time |
| Device ID | No | `--uuid`, the HSM slot description, or generated at random |
| Device name | No | `--name`, defaults to the device ID |

## Build Dependencies

- CMake 3.5 or newer and a C++11 compiler
- Boost (`filesystem`, `iostreams`, `program_options`), linked statically
- libcurl
- OpenSSL 3.0 or newer
- GLib 2.0 (found with `pkg-config`)
- libp11, unless the build uses `-DDISABLE_PKCS11=ON`

## Background

These docs are written for the [meta-foundries](https://github.com/foundriesio/meta-foundries) layer. That layer builds the tool as `fio-device-register`, sets `DEVICE_API` and `OAUTH_API` at build time, and leaves `REQUIRE_FACTORY` off. In that case the factory name defaults to `fio-device-register`, and you do not need to set it.

The tool started as part of the Linux microPlatform (LmP), where it registers devices with the FoundriesFactory™ Platform. That is why the binary, some environment variables, and some `/etc/os-release` keys use the `lmp` and `factory` names. Settings that only matter with the FoundriesFactory backend are marked **FoundriesFactory only** in the docs. To register with that backend, build with `-DREQUIRE_FACTORY=ON` so the factory name can be set.

## Documentation

- [Build configuration](docs/build-configuration.md): CMake variables and feature switches
- [Runtime configuration](docs/runtime-configuration.md): command-line options, environment variables, `/etc/os-release` keys, and their order of precedence
- [Device files](docs/device-files.md): what the tool reads and writes on the device, and how it uses HSM storage

## License

Licensed under the terms in [COPYING.MIT](COPYING.MIT).
