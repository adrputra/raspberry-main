"""
Gen1a Magic Card Recovery Tool

Recovers a MIFARE Classic 1K Gen1a magic card with corrupted block 0
by using libnfc's unlocked write mode (magic backdoor commands).

=== SETUP (run once on your Raspberry Pi) ===

    sudo apt update
    sudo apt install libnfc-bin libnfc-dev

Then configure libnfc to use your PN532 I2C hat. Create/edit the config:

    sudo mkdir -p /etc/nfc
    sudo nano /etc/nfc/libnfc.conf

Add these lines:

    device.name = "PN532 over I2C"
    device.connstring = "pn532_i2c:/dev/i2c-1"

Verify the setup by running:

    nfc-list

If it says "No NFC device found", try rebooting or check I2C is enabled
(sudo raspi-config -> Interface Options -> I2C -> Enable).

=== USAGE ===

    # Recover with original UID (recommended)
    python -m src.nfc.recover_card --uid A6199F40

    # Recover with a custom UID
    python -m src.nfc.recover_card --uid DEADBEEF

    # Format the entire card (wipe all data, reset keys to default)
    python -m src.nfc.recover_card --uid A6199F40 --format

    # Dry run — only generate the .mfd file without writing
    python -m src.nfc.recover_card --uid A6199F40 --dry-run
"""

import argparse
import struct
import subprocess
import sys
import time
import os

MIFARE_1K_BLOCKS = 64
MIFARE_1K_SECTORS = 16
BLOCK_SIZE = 16
MFD_SIZE = MIFARE_1K_BLOCKS * BLOCK_SIZE  # 1024 bytes

DEFAULT_KEY = b'\xFF\xFF\xFF\xFF\xFF\xFF'
DEFAULT_ACCESS_BITS = b'\xFF\x07\x80'
DEFAULT_USER_BYTE = b'\x69'

SAK_MIFARE_CLASSIC_1K = 0x08
ATQA_MIFARE_CLASSIC_1K = (0x04, 0x00)


def compute_bcc(uid_bytes):
    """BCC = XOR of all 4 UID bytes."""
    return uid_bytes[0] ^ uid_bytes[1] ^ uid_bytes[2] ^ uid_bytes[3]


def build_block0(uid_hex):
    """
    Build a valid block 0 for MIFARE Classic 1K.
    Layout: UID(4) + BCC(1) + SAK(1) + ATQA(2) + manufacturer(8)
    """
    if len(uid_hex) != 8:
        raise ValueError(f"UID must be exactly 4 bytes (8 hex chars), got '{uid_hex}' ({len(uid_hex)} chars)")

    uid_bytes = bytes.fromhex(uid_hex)
    bcc = compute_bcc(uid_bytes)

    block0 = bytearray(BLOCK_SIZE)
    block0[0:4] = uid_bytes
    block0[4] = bcc
    block0[5] = SAK_MIFARE_CLASSIC_1K
    block0[6] = ATQA_MIFARE_CLASSIC_1K[0]
    block0[7] = ATQA_MIFARE_CLASSIC_1K[1]
    # Bytes 8-15: manufacturer data — zeros are safe for magic cards
    return bytes(block0)


def build_sector_trailer():
    """Build a default sector trailer: KeyA(6) + Access(3) + UserByte(1) + KeyB(6)"""
    return DEFAULT_KEY + DEFAULT_ACCESS_BITS + DEFAULT_USER_BYTE + DEFAULT_KEY


def build_mfd(uid_hex, format_card=False):
    """
    Build a complete 1024-byte MFD dump for MIFARE Classic 1K.
    Block 0 gets the correct UID/BCC/SAK/ATQA.
    Sector trailers get default keys and access bits.
    Data blocks are zeroed (if format) or left as zeros.
    """
    mfd = bytearray(MFD_SIZE)

    mfd[0:BLOCK_SIZE] = build_block0(uid_hex)

    for sector in range(MIFARE_1K_SECTORS):
        trailer_block = (sector * 4) + 3
        offset = trailer_block * BLOCK_SIZE
        mfd[offset:offset + BLOCK_SIZE] = build_sector_trailer()

    return bytes(mfd)


def write_mfd_file(mfd_data, filepath):
    with open(filepath, 'wb') as f:
        f.write(mfd_data)
    print(f"Created MFD dump: {filepath} ({len(mfd_data)} bytes)")


def print_block0_info(uid_hex):
    uid_bytes = bytes.fromhex(uid_hex)
    bcc = compute_bcc(uid_bytes)
    block0 = build_block0(uid_hex)

    print("\n--- Block 0 layout ---")
    print(f"  UID:  {uid_hex.upper()} ({' '.join(f'{b:02X}' for b in uid_bytes)})")
    print(f"  BCC:  0x{bcc:02X} (computed XOR of UID bytes)")
    print(f"  SAK:  0x{SAK_MIFARE_CLASSIC_1K:02X} (MIFARE Classic 1K)")
    print(f"  ATQA: 0x{ATQA_MIFARE_CLASSIC_1K[0]:02X} 0x{ATQA_MIFARE_CLASSIC_1K[1]:02X}")
    print(f"  Full: {block0.hex().upper()}")
    print()


def run_nfc_mfclassic(mfd_path):
    """Run nfc-mfclassic with unlocked write (W) to restore the card via Gen1a backdoor."""
    cmd = ['nfc-mfclassic', 'W', 'a', 'u', mfd_path]
    print(f"Running: {' '.join(cmd)}")
    print("Place the bricked card on the reader...")
    for i in range(5, 0, -1):
        print(f"  Starting in {i}...", end='\r')
        time.sleep(1)
    print("  Writing now!        \n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        if result.returncode == 0:
            print("SUCCESS — Card block 0 has been restored!")
            print("Try scanning the card with your PN532 or phone to verify.")
        else:
            print(f"nfc-mfclassic exited with code {result.returncode}")
            print("Make sure the card is placed on the reader and libnfc is configured.")
        return result.returncode == 0
    except FileNotFoundError:
        print("ERROR: 'nfc-mfclassic' not found.")
        print("Install it with: sudo apt install libnfc-bin")
        return False
    except subprocess.TimeoutExpired:
        print("ERROR: Timed out waiting for card. Place the card on the reader and try again.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Recover a bricked Gen1a MIFARE Classic 1K magic card using libnfc'
    )
    parser.add_argument(
        '--uid', required=True,
        help='Original 4-byte UID in hex (e.g. A6199F40)'
    )
    parser.add_argument(
        '--format', action='store_true', default=False,
        help='Format the entire card (wipe all data, reset all keys to default)'
    )
    parser.add_argument(
        '--dry-run', action='store_true', default=False,
        help='Only generate the .mfd file, do not write to card'
    )
    parser.add_argument(
        '--output', default=None,
        help='Output path for the .mfd file (default: recover_<uid>.mfd)'
    )
    args = parser.parse_args()

    uid = args.uid.replace(' ', '').replace(':', '').replace('-', '')
    if len(uid) != 8 or not all(c in '0123456789abcdefABCDEF' for c in uid):
        print(f"ERROR: Invalid UID '{args.uid}'. Must be exactly 4 bytes (8 hex chars).")
        sys.exit(1)

    print_block0_info(uid)

    mfd_data = build_mfd(uid, format_card=args.format)

    mfd_path = args.output or f"recover_{uid.upper()}.mfd"
    write_mfd_file(mfd_data, mfd_path)

    if args.dry_run:
        print("Dry run — skipping card write.")
        print(f"To write manually: nfc-mfclassic W a u {mfd_path}")
        return

    run_nfc_mfclassic(mfd_path)


if __name__ == '__main__':
    main()
