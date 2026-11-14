# [CVE-TBD] D-Link DCS-6501LH V3.03.02 Invalid Free in RTSP Digest Authentication

## VulDB Submission Fields

- Vendor: D-Link
- Product: DCS-6501LH (DCS6501LHCx)
- Version or Commit: V3.03.02 (firmware package DCS6501LHCx_FW303B02_SD)
- Vulnerability: Free of Memory not on the Heap (CWE-590)
- Advisory / Exploit URL: https://github.com/Zimo-666/D-Link-DCS-6501LH-cves/tree/main/02-rtsp-digest-invalid-free
- Description:

```
An invalid free vulnerability was discovered in D-Link DCS-6501LH camera firmware v3.03.02. ValidateAuthorizationHeader in the aoni_ipc RTSP server parses the uri parameter of a Digest Authorization header; when the value does not contain "rtsp://", the code keeps a pointer into the request buffer instead of the heap object returned by ParseURI and later calls free() on it when the value does not match the session name. The crash happens while the credentials are parsed, so no valid credentials are needed. Reproduction: send the TEARDOWN request in poc.py to an existing RTSP session (the built-in echoshow session created at startup) with an Authorization header whose uri is "/x"; glibc reports "free(): invalid pointer" and the daemon aborts, while the same request with a uri of the form rtsp://host/live/echoshow/video returns a normal 401 Unauthorized and leaves the service running. Verified two out of two times for each variant in an emulated environment running the stock aoni_ipc binary. Impact: unauthenticated remote denial of service; the supervisory process restarts the daemon, so repeated requests keep the RTSP and control service unavailable and can drive a device reboot. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5).
```

---

## Technical Disclosure

### Summary

The RTSP server of `aoni_ipc` validates Digest credentials in
`ValidateAuthorizationHeader`. The `uri` parameter of the Authorization header
is handled differently depending on whether it starts with `rtsp://`: a value
that contains `rtsp://` is replaced by a heap allocation from `ParseURI`,
while any other value leaves a pointer into the request buffer. On the
subsequent mismatch against the session name, the code unconditionally calls
`free()` on that pointer, which glibc rejects as an invalid free and aborts
the process.

### Affected Product and Firmware

- Vendor: D-Link
- Product: DCS-6501LH (DCS6501LHCx), indoor network camera
- Firmware: V3.03.02, package `DCS6501LHCx_FW303B02_SD.bin`
  (image 16,025,960 bytes, sha256
  `8751e1219ddfd839f59a3b01b2ecace2ecf3c9b95cc83f8278886bc87e0652c1`)
- Application build: `AONI_IPC Make On Aug  4 2025 18:08:26 V3.03.02`
- Platform: Ingenic T31, MIPS32 little-endian, Linux 3.10.14

### Vulnerability Details and Root Cause

`ValidateAuthorizationHeader` at `0x004F5FC8` in the stripped `aoni_ipc`
binary extracts the `uri` parameter of the Digest header:

```c
v20 = strstr(RequestMsgHeader, "uri");
v21 = v20;
if (!v20 || (v22 = v20 + 5, (v23 = strchr(v20 + 5, '"')) == 0))
    return 401;
v24 = v21 + 6;                       /* pointer into the request buffer */
if (!strstr(v22, "rtsp://"))
    goto LABEL_28;                   /* keeps the non-heap pointer */
v24 = ParseURI(v22, 3, "/");         /* heap allocation */
...
LABEL_28:
v25 = strlen(session_name);
if (memcmp(v24, session_name, v25)) {
    free(v24);                       /* invalid free at 0x004F631C */
    return 401;
}
```

When the `uri` value has no `rtsp://` prefix and does not equal the session
name, `free()` receives an interior pointer into the received message. glibc
aborts with `free(): invalid pointer`.

### Vulnerable Component, Function and Call Chain

- Component: RTSP server in `aoni_ipc`
- Entry: `RTSPTeardownHandle` (`0x004F6624`) -> `ValidateAuthorizationHeader`
  (`0x004F5FC8`), invalid free at `0x004F631C`
- The session must exist; the built-in `echoshow` session
  (`rtsp://<host>/live/echoshow/video`) is created at startup and answers a
  Digest challenge without credentials.

### Authentication Requirements and Attack Conditions

- No valid credentials: the abort occurs while the supplied credentials are
  being parsed, before any password comparison.
- The attacker needs network reachability to TCP port 554 and knowledge of an
  existing session path; the built-in `echoshow` path is fixed in the firmware.
- No user interaction and no configuration change are required.

### Proof of Concept and Reproduction

The PoC is `poc.py` in this directory. It sends two TEARDOWN requests to
`/live/echoshow/video`: a control with a well-formed `rtsp://` uri and the
trigger with `uri="/x"`.

```bash
python3 poc.py <host> [port]
```

Expected result on a vulnerable device: the control request returns
`401 Unauthorized` with a `WWW-Authenticate: Digest` header and the service
stays up; the trigger request gets no response, glibc logs
`free(): invalid pointer`, and the RTSP daemon aborts.

Observed in the emulated environment with the stock binary:

```
control : RTSP/1.0 401 Unauthorized ... (service alive)
trigger : no response; "free(): invalid pointer: 0x0078a2a4"; SIGABRT
```

### Observed Results and Evidence

Each variant was executed twice against a freshly started instance:

1. Control (`uri="rtsp://<host>:554/live/echoshow/video"`): `401 Unauthorized`,
   `WWW-Authenticate: Digest realm="", nonce="..."`, process alive in both runs.
2. Trigger (`uri="/x"`): no RTSP response; the daemon log records
   `*** glibc detected *** ... free(): invalid pointer: 0x0078a2a4 ***` and the
   process terminates with SIGABRT in both runs.

The differing outcome for otherwise identical requests isolates the `uri`
parameter handling as the cause.

### Security Impact

Unauthenticated remote denial of service. The main application aborts; the
supervisory `daemon` restarts it, so a repeated request stream keeps RTSP,
streaming and control unavailable and can drive the watchdog to reboot the
device. No information disclosure or code execution was demonstrated for this
issue.

### CWE and CVSS

- CWE-590: Free of Memory not on the Heap
- CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5)

### Related CVEs and Novelty

The only public issues for this firmware version are CVE-2026-125079
(hard-coded credentials in `SystemConfig.ini`) and CVE-2026-113735 (weak
credential in `mydlink_set_root_pwd`). Both concern credential values, not the
RTSP authentication parser, and neither involves an invalid free. This issue is
also independent of the RTSP request-parser heap overflow reported separately
for the same product (different function, different root cause, different fix).

### Suggested Remediation

- Only call `free()` on pointers returned by `ParseURI`/`malloc`; track the
  allocation explicitly and never free a pointer into the request buffer.
- Reject Digest headers whose `uri` parameter is not an absolute `rtsp://` URI.
- Add a defensive check that the pointer being freed lies on the heap.

### Disclosure Status

- Reported to the vendor: yes.
- CVE assigned: no (CVE-TBD).
- Public disclosure: this directory only; no public advisory yet.
