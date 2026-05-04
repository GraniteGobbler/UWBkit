#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import time

try:
    import serial
except ImportError:
    print("Missing dependency: pyserial. Install with: pip install pyserial", file=sys.stderr)
    sys.exit(1)

SYNC = b'\xAB\xCD'


def crc16_ccitt(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def read_exact(ser, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = ser.read(n - len(buf))
        if not chunk:
            raise TimeoutError("Serial timeout while reading frame")
        buf.extend(chunk)
    return bytes(buf)


def find_sync(ser) -> bool:
    prev = b''
    while True:
        b = ser.read(1)
        if not b:
            return False
        prev = (prev + b)[-2:]
        if prev == SYNC:
            return True


def main():
    ap = argparse.ArgumentParser(description="Read UART-framed ZEP packets from serial and forward to UDP/17754 for Wireshark")
    ap.add_argument("--port", required=True, help="Serial port, e.g. COM5 or /dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200, help="Baud rate")
    ap.add_argument("--host", default="127.0.0.1", help="UDP destination host")
    ap.add_argument("--udp-port", type=int, default=17754, help="UDP destination port")
    ap.add_argument("--timeout", type=float, default=5.0, help="Serial timeout in seconds")
    ap.add_argument("--max-len", type=int, default=2048, help="Maximum accepted ZEP packet length")
    ap.add_argument("--verbose", action="store_true", help="Print packet diagnostics")
    ap.add_argument("--log-wait", action="store_true", help="Log when no sync has been received yet")
    args = ap.parse_args()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    with serial.Serial(args.port, args.baud, timeout=args.timeout) as ser:
        if args.verbose:
            print(f"Listening on {args.port} @ {args.baud}, forwarding to udp://{args.host}:{args.udp_port}")
        synced_once = False
        while True:
            try:
                got_sync = find_sync(ser)
                if not got_sync:
                    if args.verbose and args.log_wait:
                        print("Waiting for sync...")
                    continue
                if args.verbose and not synced_once:
                    print("Sync acquired")
                synced_once = True
                hdr = read_exact(ser, 2)
                zep_len = struct.unpack('<H', hdr)[0]
                if zep_len == 0 or zep_len > args.max_len:
                    if args.verbose:
                        print(f"Skipping invalid length {zep_len}")
                    continue
                zep_pkt = read_exact(ser, zep_len)
                crc_rx = struct.unpack('<H', read_exact(ser, 2))[0]
                crc_calc = crc16_ccitt(zep_pkt)
                if crc_rx != crc_calc:
                    if args.verbose:
                        print(f"CRC mismatch rx=0x{crc_rx:04X} calc=0x{crc_calc:04X}")
                    continue
                udp.sendto(zep_pkt, (args.host, args.udp_port))
                if args.verbose:
                    print(f"Forwarded {len(zep_pkt)} bytes @ {time.strftime('%H:%M:%S')}")
            except KeyboardInterrupt:
                break
            except Exception as e:
                if args.verbose:
                    print(f"Recoverable error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
