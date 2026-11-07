# vTPM2

**vTPM2** is a software-based TPM 2.0 implementation for Windows 10 and Windows 11.

It provides a TPM 2.0 command-processing engine hosted by a Windows user-mode service, with persistent state, an HTTP interface, a local web dashboard, and a command-line client.

## Features

- TPM 2.0 command processing and cryptographic operations
- Authorization and policy sessions
- PCR, NV storage, hierarchy, clock, and state-management functionality
- Windows service integration
- Local HTTP API and dashboard
- Command-line client
- PowerShell scripts for installing and removing the service

## Components

- `src/engine/` — TPM 2.0 engine
- `src/service/` — Windows service, API, and dashboard
- `src/cli/` — command-line client
- `installer/` — Windows service installation and removal scripts

## Important limitations

vTPM2 is a **software TPM**, not a hardware security module. It does not provide hardware-rooted trust, hardware-backed attestation, or measured boot. On a standard physical Windows installation, it is not recognized by Windows Security as a platform TPM and does not replace a firmware-backed TPM for features such as BitLocker or Windows Hello.

The service exposes its local interface at `http://127.0.0.1:8082`.

## Configuration

An example service configuration is provided at `src/service/config.json.example`.

## License

Add the project license here. The TPM engine includes its upstream license file at `src/engine/LICENSE`; retain applicable third-party license and attribution notices when redistributing the source.
