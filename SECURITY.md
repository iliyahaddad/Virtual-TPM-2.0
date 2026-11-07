# SECURITY

vTPM2 — Software TPM 2.0 for Windows.

## Trust model

vTPM2 is a **software TPM**, not a hardware security boundary. It provides the
TPM 2.0 protocol and semantics (command processing, PCR, NV storage, attestation
commands, key derivation) entirely in software. State lives in host memory and in
a JSON snapshot on disk.

Do **not** use vTPM2 for:
- production secrets or keys of real value,
- BitLocker drive encryption,
- Windows Hello / biometric authentication,
- authentic measured boot or remote attestation,
- any security boundary that requires hardware-rooted trust.

## Claims vTPM2 does NOT make

- No hardware-rooted trust.
- No genuine hardware attestation.
- No hardware-backed key isolation.
- No authentic physical measured boot.
- No secure hardware protection.
- No Windows Security recognition as a platform TPM.

## What vTPM2 does not do (by design)

- Does not fabricate measured boot evidence.
- Does not create fake PCR measurements (PCR values are real outputs of the
  software TPM engine, but they are software-generated, not firmware-measured).
- Does not falsify Windows security status.
- Does not silently disable Secure Boot.
- Does not silently disable driver signature enforcement.
- Does not silently disable BitLocker.
- Does not silently modify Windows boot configuration.
- Does not bypass Windows security controls.

## Privileged operations

Any installation, driver loading, or firmware operation requires explicit
administrator consent. vTPM2 does not automatically modify firmware or boot
configuration, does not automatically enable Test Mode, and does not disable
Secure Boot to force installation.

## State protection

TPM persistent state (hierarchy seeds, EK/SRK sensitive areas, NV data, clock)
is stored under `%PROGRAMDATA%\vTPM2\tpm-state.json`. The state directory is
created `0o700` (owner-only) by the go-sdk-vtpm2 `state` package. The snapshot
is JSON (not encrypted). Hierarchy seeds and private keys are **never** written
to the GUI or logs.

Because this is a software TPM, on-disk state is protected only by file-system
ACLs, not by hardware isolation. An administrator or process with sufficient
access to the state directory can read the snapshot.

## Service security

The vTPM2 service runs as a normal Windows service (or console app). The HTTP
dashboard/API bind to `127.0.0.1` only (loopback), so they are not reachable
from the network. Raw TPM commands are accepted over the loopback API.

## Kernel driver (reference)

The reference driver in `src/driver/` is not built or signed. A kernel driver
would run with full system privileges and would require WHQL signing (or Test
Mode) to load. It is not part of the validated release.

## Responsible use

Treat vTPM2 as a development/educational tool for learning TPM 2.0 command
processing and Windows integration, not as a substitute for a hardware TPM.
