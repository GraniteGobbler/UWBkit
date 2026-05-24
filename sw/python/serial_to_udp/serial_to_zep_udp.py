#!/usr/bin/env python3
"""
uart_zep_forward.py — UART-framed ZEP packet bridge for Wireshark.

Reads UART frames from a serial port (produced by wrap_uart_frame() on the
embedded side), verifies their CRC16-CCITT checksum, strips the framing, and
forwards the bare ZEP payload as a UDP datagram to localhost:17754 so that
Wireshark can decode it in real time using its built-in ZEP dissector.

Frame format expected on the serial port:
  [0xAB][0xCD] | length (uint16 LE) | ZEP payload (length bytes) | CRC16 (uint16 LE)
"""
import argparse
import socket
import struct
import sys
import time


# Handle missing pyserial so the user gets an actionable message
# rather than a bare ImportError traceback.
try:
    import serial
except ImportError:
    print("Missing dependency: pyserial. Install with: pip install pyserial", file=sys.stderr)
    sys.exit(1)


# Two-byte sync preamble that marks the start of every UART frame.
# Must match UART_SYNC0 / UART_SYNC1 defined on the embedded side.
SYNC = b'\xAB\xCD'


def crc16_ccitt(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    """
    Compute CRC16-CCITT over *data*.

    Uses the standard CCITT parameters: polynomial 0x1021, initial value
    0xFFFF, MSB-first bit processing.  Must produce identical results to the
    crc16_ccitt() C function on the embedded side so that integrity checks
    across the UART link are meaningful.

    Args:
        data: Byte string to checksum.
        poly: Generator polynomial (default 0x1021).
        init: Initial CRC register value (default 0xFFFF).

    Returns:
        16-bit CRC as an integer in the range [0, 0xFFFF].
    """
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
    """
    Read exactly *n* bytes from the serial port, blocking until they arrive.

    pyserial's ser.read(n) may return fewer than *n* bytes if the timeout
    fires before the buffer fills.  This wrapper retries until the requested
    count is satisfied or the port signals a timeout with an empty read.

    Args:
        ser: Open pyserial Serial instance.
        n:   Number of bytes to read.

    Returns:
        Exactly *n* bytes.

    Raises:
        TimeoutError: If the serial port returns an empty read before *n*
                      bytes have been collected, indicating the device stopped
                      transmitting mid-frame.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = ser.read(n - len(buf))
        if not chunk:
            raise TimeoutError("Serial timeout while reading frame")
        buf.extend(chunk)
    return bytes(buf)


def find_sync(ser) -> bool:
    """
    Scan the incoming byte stream until the two-byte SYNC preamble is found.

    Reads one byte at a time and keeps a rolling two-byte window.  This
    approach handles partial frames, noise bytes, and mid-stream connection
    starts gracefully — the receiver re-synchronises automatically on the
    next valid preamble rather than getting stuck on stale data.

    Args:
        ser: Open pyserial Serial instance.

    Returns:
        True once SYNC is found.
        False if the serial port times out before SYNC is detected (empty read).
    """
    prev = b''
    while True:
        b = ser.read(1)
        if not b:
            return False
        prev = (prev + b)[-2:]  # Keep only the last two bytes seen
        if prev == SYNC:
            return True


def main():
    # --- Argument parsing ---------------------------------------------------
    ap = argparse.ArgumentParser(description="Read UART-framed ZEP packets from serial and forward to UDP/17754 for Wireshark")
    ap.add_argument("--port",     required=True,           help="Serial port, e.g. COM5 or /dev/ttyUSB0")
    ap.add_argument("--baud",     type=int, default=115200, help="Baud rate")
    ap.add_argument("--host",     default="127.0.0.1",     help="UDP destination host")
    ap.add_argument("--udp-port", type=int, default=17754,  help="UDP destination port")
    ap.add_argument("--timeout",  type=float, default=5.0,  help="Serial timeout in seconds")
    ap.add_argument("--max-len",  type=int, default=6300,   help="Maximum accepted ZEP packet length")
    ap.add_argument("--verbose",  action="store_true",      help="Print packet diagnostics")
    ap.add_argument("--log-wait", action="store_true",      help="Log when no sync has been received yet")
    args = ap.parse_args()

    # --- UDP socket (connectionless, fire-and-forget to Wireshark) ----------
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # --- Main receive / forward loop ----------------------------------------
    with serial.Serial(args.port, args.baud, timeout=args.timeout) as ser:
        if args.verbose:
            print(f"Listening on {args.port} @ {args.baud}, forwarding to udp://{args.host}:{args.udp_port}")
        synced_once = False     # Used to print "Sync acquired" exactly once
        while True:
            try:
                # Hunt for the two-byte frame preamble.
                got_sync = find_sync(ser)
                if not got_sync:
                    if args.verbose and args.log_wait:
                        print("Waiting for sync...")
                    continue

                if args.verbose and not synced_once:
                    print("Sync acquired")
                synced_once = True

                # Read the 2-byte little-endian ZEP frame length.
                hdr = read_exact(ser, 2)
                zep_len = struct.unpack('<H', hdr)[0]

                # Reject zero-length and suspiciously large frames before
                # attempting to read their payload; avoids stalling or OOM.
                if zep_len == 0 or zep_len > args.max_len:
                    if args.verbose:
                        print(f"Skipping invalid length {zep_len}")
                    continue

                # Read the ZEP frame.
                zep_pkt = read_exact(ser, zep_len)

                # Read the 2-byte little-endian CRC and verify it.
                crc_rx   = struct.unpack('<H', read_exact(ser, 2))[0]
                crc_calc = crc16_ccitt(zep_pkt)
                if crc_rx != crc_calc:
                    if args.verbose:
                        print(f"CRC mismatch rx=0x{crc_rx:04X} calc=0x{crc_calc:04X}")
                    continue    # Discard corrupted frame; re-sync on next preamble

                # Forward the verified ZEP frame over UDP.
                # Wireshark (with a "ZEP" capture filter or dissector on port
                # 17754) will decode this as an IEEE 802.15.4 frame.
                udp.sendto(zep_pkt, (args.host, args.udp_port))
                if args.verbose:
                    print(f"Forwarded {len(zep_pkt)} bytes @ {time.strftime('%H:%M:%S')}")

            except KeyboardInterrupt:
                break   # Clean exit on Ctrl-C; the `with` block closes the port
            except Exception as e:
                # All other exceptions (TimeoutError, struct errors, etc.) are
                # treated as recoverable: log them if verbose and attempt to
                # re-sync on the next loop iteration rather than crashing.
                if args.verbose:
                    print(f"Recoverable error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()