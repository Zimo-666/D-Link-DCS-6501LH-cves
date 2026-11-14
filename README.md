# D-Link DCS-6501LH Security Advisories

Security vulnerabilities discovered in the **D-Link DCS-6501LH (DCS6501LHCx)**
indoor network camera, firmware **V3.03.02** — the latest publicly available
firmware at the time of research.

- Firmware package: `DCS6501LHCx_FW303B02_SD.bin`
- Image size / sha256: 16,025,960 bytes /
  `8751e1219ddfd839f59a3b01b2ecace2ecf3c9b95cc83f8278886bc87e0652c1`
- Application: `aoni_ipc` (build `V3.03.02`, Aug 4 2025)
- Platform: Ingenic T31, MIPS32 little-endian, Linux 3.10.14

All findings were verified against the stock firmware binaries in an emulated
environment; every advisory documents the control behaviour (non-crashing
request) alongside the trigger, and PoC scripts are non-destructive.

## Advisories

| # | Title | Type | CVSS 3.1 | Auth |
|---|---|---|---|---|
| 1 | [Heap buffer overflow in the RTSP request parser](01-rtsp-parser-heap-overflow) (port 554, ≥32 headers) | CWE-787 | 7.1 | none |
| 2 | [Invalid free in RTSP Digest authentication](02-rtsp-digest-invalid-free) (port 554, `uri` parameter) | CWE-590 | 6.5 | none |
| 3 | [Stack buffer overflow in the RTSP Digest `username` copy](03-rtsp-digest-username-overflow) (port 554, ≥352-byte username) | CWE-121 | 8.8 | none |
| 4 | [Stack buffer overflow via StreamProxy `Content-Length` body copy](04-streamproxy-content-length-body-overflow) (port 7000, plaintext HTTP) | CWE-121 | 8.8 | none |
| 5 | [Stack buffer overflow via StreamProxy `Content-Length` header line](05-streamproxy-content-length-header-overflow) (port 7000, plaintext HTTP) | CWE-121 | 8.8 | none |

Issues 1–3 affect the RTSP server (TCP 554, enabled by default); issues 4–5
affect the mydlink StreamProxy listener (TCP 7000, started during normal
boot). All five are reachable without credentials; 3–5 demonstrate control of
the instruction pointer (`pc = ra = 0x41414141`) in the root-privileged
`aoni_ipc` daemon.

The previously published issues for this firmware — CVE-2026-125079
(hard-coded credentials) and CVE-2026-113735 (weak credential handling) — are
credential problems and unrelated to the memory-safety defects listed here.

## Notes

- Each advisory directory contains the full technical disclosure
  (`README.md`) and a runnable, non-destructive PoC (`poc.py`).
- The advisories are five distinct defects with independent root causes and
  fixes; the per-advisory "Related CVEs and Novelty" sections explain the
  separation.
- Vendor notification: pending at publication time; coordinated disclosure
  timeline will be updated here.
