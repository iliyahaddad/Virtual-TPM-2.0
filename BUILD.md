# BUILD

vTPM2 — Software TPM 2.0 for Windows.

## Build environment used (verified)

- Windows 10/11 x64 (physical host)
- Go 1.23.4 (`go version go1.23.4 windows/amd64`)
- Windows Kits 10 present (no WDK/KMDF headers, no signing toolchain)
- No .NET SDK, no internet-dependent module downloads required

Go 1.23.4 toolchain is used directly. The go-sdk-vtpm2 engine is integrated
directly under `src/engine/` (module `github.com/deploymenttheory/go-sdk-vtpm2`,
go directive retargeted to `go 1.23` for the local toolchain). The engine has
no external dependencies beyond the Go standard library. The original
`go-sdk-vtpm2-main` repository was not modified.

## Building the TPM engine (verified)

```
cd C:\Users\manshadi.PDF\Desktop\vTPM2\src\engine
$env:GOTOOLCHAIN='local'          # only needed if a newer toolchain is configured
$env:GOPROXY='off'                # use module cache only
go build ./tpm2/... ./state/... ./client/...
go test ./tpm2/... ./state/... ./client/...
```

Result: all three packages build and their tests pass (tpm2: 221+ tests).

## Building the Windows service (verified)

```
cd C:\Users\manshadi.PDF\Desktop\vTPM2\src\service
$env:GOTOOLCHAIN='local'
$env:GOPROXY='off'
go mod tidy
go build ./...          # produces vtpmservice.exe
go vet ./...
```

The service module vendors go-sdk-vtpm2 via a `replace` directive pointing at
`../engine`; `golang.org/x/sys v0.23.0` (Windows service API) is resolved from
the module cache. `go mod tidy` regenerates `go.sum` offline.

Run interactively:
```
vtpmservice.exe           # console mode; HTTP dashboard on 127.0.0.1:8082
```

Install as a Windows service (admin):
```
sc create vTPM2 binPath= "C:\path\to\vtpmservice.exe" start= demand
sc start vTPM2
sc stop vTPM2
sc delete vTPM2
```

The binary detects whether it was launched by the SCM (`svc.IsWindowsService`) and
runs as a service or console app accordingly.

## Kernel driver (NOT built)

`src/driver/` holds reference KMDF source only. It cannot be compiled in this
environment (no WDK/KMDF headers, no signing toolchain) and is not signed, so it
cannot be loaded on stock Windows 10/11. See WINDOWS_TPM_FEASIBILITY.md and
src/driver/README.md.

## Verification summary

- Engine: build OK, tests OK (221+ tests).
- Service: build OK, vet OK, integration tests OK (7 tests).
- CLI: build OK, vet OK.
- Top-level integration tests OK (18 tests).
- Process restart persistence tests OK.
- Runtime: Startup/GetCapability/GetRandom/PCR/NV/backup/restore all exercised
  successfully over the HTTP API; state persisted across a service restart.
