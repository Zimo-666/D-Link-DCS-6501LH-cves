# [CVE-TBD] D-Link DCS-6501LH V3.03.02 Unauthenticated Heap Buffer Overflow in RTSP Request Parser

## VulDB Submission Fields

- Vendor: D-Link
- Product: DCS-6501LH (DCS6501LHCx)
- Version or Commit: V3.03.02 (firmware package DCS6501LHCx_FW303B02_SD)
- Vulnerability: Heap-based Buffer Overflow (CWE-787)
- Advisory / Exploit URL: https://github.com/Zimo-666/D-Link-DCS-6501LH-cves/tree/main/01-rtsp-parser-heap-overflow
- Description:

```
A heap-based buffer overflow (out-of-bounds write) vulnerability was
discovered in D-Link DCS-6501LH camera firmware v3.03.02. The RTSP
server of the aoni_ipc application allocates a fixed 276-byte request
object in RTSPServerParseMessage and stores every parsed header as a
pointer pair at v5[2*count+5] / v5[2*count+6] without bounding the
header count, so a request carrying more than 31 headers writes past
the end of the allocation. The 32nd header already writes 8 bytes past
the 276-byte chunk, and every additional header extends the overflow
by another 8 bytes (two heap pointers), up to the size that the RTSP
receive path accepts. Parsing happens before any
authentication check, and the service is reachable on TCP port 554
without credentials. Reproduction: run the PoC script in this
directory against port 554 of the target (an OPTIONS request with 32
header lines); the server answers with a corrupted 200 OK whose first
four bytes are a heap pointer instead of "RTSP/1.0", then the process
aborts because of glibc heap corruption. Verified six out of six times
in an emulated environment running the stock aoni_ipc binary, where the
daemon died with SIGABRT right after the corrupted response was sent.
Impact: unauthenticated remote denial of service (repeated crashes
drive the watchdog to restart or reboot the device) and disclosure of
heap pointer values together with corruption of adjacent heap objects,
which can be developed further towards code execution. Proposed
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H (7.1).
```

---

## Technical Disclosure

### Summary

The RTSP server embedded in `aoni_ipc` (the main application of the
D-Link DCS-6501LH) parses incoming RTSP requests into a fixed-size heap
object of 276 bytes. The number of header fields that may be stored in
that object is never validated. Every header beyond the 31st writes two
attacker-influenced heap pointers past the end of the allocation,
corrupting adjacent heap chunks. The overflow occurs during message
parsing, i.e. before authentication, and is triggerable over TCP port
554 with a single request that contains no credentials.

### Affected Product and Firmware

- Vendor: D-Link
- Product: DCS-6501LH (DCS6501LHCx), indoor network camera
- Firmware: V3.03.02, package `DCS6501LHCx_FW303B02_SD.bin`
  (`DCS6501LHCx_FW303B02_SD.zip`, image 16,025,960 bytes,
  sha256 `8751e1219ddfd839f59a3b01b2ecace2ecf3c9b95cc83f8278886bc87e0652c1`)
- Application build: `AONI_IPC Make On Aug  4 2025 18:08:26 V3.03.02`
- Platform: Ingenic T31, MIPS32 little-endian, Linux 3.10.14

The RTSP server is enabled by default; no configuration change is
required to expose port 554.

### Vulnerability Details and Root Cause

`RTSPServerParseMessage` (virtual address `0x004F28AC` in the stripped
`aoni_ipc` binary) allocates the request descriptor with:

```c
v3 = (int *)malloc(0x114);   /* 276 bytes = 69 pointer-sized slots */
v5 = v3;
```

Slots 0..4 of the descriptor hold metadata (CSeq, header count, URI,
RTSP version, method). Parsed headers are stored as two dwords each:
the header name pointer and the header value pointer. For the header at
zero-based index `count`, the code computes:

```c
v34 = v5[1] + 2;             /* v5[1] is the running header count */
v35 = malloc(v30 + 1);       /* header name string */
v5[2 * v34 + 1] = v35;       /* name  -> index 2*count + 5 */
...
v45 = &v5[2 * v34];          /* index 2*count + 4 */
v45[2] = v44;                /* value -> index 2*count + 6 */
v5[1] = v49 + 1;             /* count += 1, no upper bound */
```

The allocation has 69 dwords (indices 0..68). Header index 31 uses
indices 67 and 68, which still fit. Header index 32 writes to indices
69 and 70, i.e. the first 8 bytes past the end of the chunk; each
further header extends the overflow by another 8 bytes. The parse loop
is only bounded by the number of bytes left in the received message
(`if (v27 < 3) break;`), never by a header count, so the out-of-bounds
write is attacker controlled in length: each extra header line adds
another 8 bytes past the allocation.

Because the written values are real heap pointers returned by `malloc`
(the parsed name/value strings), each overflowing header overwrites the
beginning of the next heap chunk with two valid pointers. In the
observed case the adjacent object was the RTSP response buffer: its
first four bytes were replaced by the pointer `0x0078A640`, which was
then transmitted to the client as the start of the response.

### Vulnerable Component, Function and Call Chain

- Component: RTSP server in `aoni_ipc`
- Entry point: TCP port 554, `HandleDlinkRTSP` (`0x004F8770`)
- Call chain:
  `HandleDlinkRTSP` -> `RTSPServerParseMessage` (`0x004F28AC`) ->
  `malloc(0x114)` + unbounded header loop
- Fault: heap out-of-bounds write starting at header #32
  (store instructions at `0x004F2BF4` for the name pointer and
  `0x004F2CB8` for the value pointer)
- Receive path: `rtsp_receive_socket` (`0x00490624`) reads up to
  `0x7FF` bytes per call, so a request carrying 32 or more header lines
  is accepted intact; a 32-header request is only 351 bytes long.

### Authentication Requirements and Attack Conditions

- No authentication is needed: the request used in the PoC contains no
  `Authorization` header, and the overflow happens inside the parser
  before any credential check or session lookup.
- The attacker only needs network reachability to TCP port 554
  (local network by default; internet if the camera is port-forwarded).
- No user interaction, no configuration change, and no prior session
  are required. A single request is sufficient.

### Proof of Concept and Reproduction

The PoC is the `poc.py` script in this directory. It opens a TCP
connection to the target and sends an RTSP request whose header section
contains 32 generated header lines (`X0` .. `X31`):

```
OPTIONS rtsp://<host>:<port>/ RTSP/1.0
CSeq: 7
X0: v0
X1: v1
...
X31: v31

```

Run:

```bash
python3 poc.py <host> [port]
```

The script first sends a control request with 31 headers (expected:
clean `RTSP/1.0 200 OK`) and then the 32-header request, printing both
responses as hexadecimal and ASCII.

Expected result on a vulnerable device: the control response starts
with `RTSP/1.0 200 OK`, while the 32-header response starts with four
bytes of a heap pointer (for example `40 a6 78 20`) followed by
`200 OK`, and the RTSP process terminates because glibc detects heap
corruption.

Reference session against the stock binary in an emulated environment
(service freshly started for each run):

```
$ python3 poc.py <host>
[*] control (31 headers): RTSP/1.0 200 OK (152 bytes)
    prefix: 52 54 53 50 2f 31 2e 30 ...   "RTSP/1.0"
[*] overflow (32 headers): 147 bytes
    prefix: 40 a6 78 20 32 30 30 20 4f 4b ...  "\\x40\\xa6x 200 OK"
[!] service died after the overflow request (SIGABRT, heap corruption)
```

Normal input therefore returns a well-formed RTSP response, whereas the
32-header request corrupts the response object and kills the daemon.

### Observed Results and Evidence

Repeated six times (three runs with 32 headers, three with 33 headers)
against a fresh instance of the stock `aoni_ipc` RTSP service; all six
runs produced the same behaviour:

1. The response no longer begins with the RTSP status line but with
   heap pointer bytes (`40 a6 78 20` = pointer `0x0078A640`), which is
   direct evidence that an adjacent heap object was overwritten with a
   heap pointer and that heap contents are disclosed to the client.
2. The RTSP daemon terminated with an uncaught `SIGABRT`
   (`qemu: uncaught target signal 6 (Aborted)`), the expected outcome
   of glibc detecting heap metadata corruption caused by the
   out-of-bounds write.
3. Requests with 31 headers returned a clean `RTSP/1.0 200 OK`
   response and left the service running.

The same corruption of the response prefix was observed for
`DESCRIBE` and `SETUP` requests carrying 32 headers sent without any
credentials, confirming that the flaw is independent of the RTSP
method and of the authentication state.

### Security Impact

- Unauthenticated remote denial of service: one request aborts the main
  application. On a real device the supervisory `daemon` restarts
  `aoni_ipc`; repeated requests keep the camera's streaming and control
  service down and, after enough restarts, drive the watchdog to reboot
  the device.
- Heap memory disclosure: pointer values from the corrupted chunk are
  returned to the client inside the RTSP response.
- Heap corruption of adjacent objects with valid, attacker-influenced
  pointers per overflowing header. This is a controllable out-of-bounds
  write of pointer-sized values, which is a realistic path towards
  remote code execution under the constraints of a 32-bit MIPS glibc
  heap, although code execution was not demonstrated in this report.

### CWE and CVSS

- CWE-787: Out-of-bounds Write (heap-based buffer overflow)
- CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H (7.1)

The score reflects the demonstrated consequences (unauthenticated
adjacent heap corruption, heap pointer disclosure and reliable process
abort) and does not assume code execution.

### Related CVEs and Novelty

Public information about DCS-6501LH V3.03.02 is limited to credential
issues unrelated to this flaw: CVE-2026-125079 (hard-coded credentials
in `SystemConfig.ini` / `mydlink_default_sys_info`) and CVE-2026-113735
(weak credential handling in `mydlink_set_root_pwd`). Neither concerns
the RTSP parser or memory corruption. No public advisory, CVE or commit
describes a heap overflow in `RTSPServerParseMessage` of `aoni_ipc`, and
the root cause here (missing bound on the header count in a fixed-size
request descriptor) is independent of those credential issues.

### Suggested Remediation

- Bound the number of stored headers against the descriptor capacity
  (69 dwords, i.e. at most 31 headers) and reject or ignore further
  headers before writing to `v5`.
- Prefer a dynamically grown header array sized from the request, with
  an explicit protocol limit that is checked before each store.
- Add a hard limit on the total request size and on the header count at
  the RTSP transport layer.
- Reject requests with an excessive number of headers with
  `400 Bad Request` and log the event.

### Disclosure Status

- Reported to the vendor: yes.
- CVE assigned: no (CVE-TBD).
- Public disclosure: this directory only; no public advisory yet.
