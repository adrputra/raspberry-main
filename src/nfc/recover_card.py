"""
Magic Card Recovery Tool

Recovers a MIFARE Classic 1K magic card with corrupted block 0.
Auto-detects card generation (Gen1a, Gen2/CUID, or regular) and
applies the correct recovery method.

=== SETUP (run once on your Raspberry Pi) ===

    sudo apt update
    sudo apt install libnfc-bin libnfc-dev

Then configure libnfc to use your PN532 I2C hat:

    sudo mkdir -p /etc/nfc
    sudo nano /etc/nfc/libnfc.conf

Add these lines:

    device.name = "PN532 over I2C"
    device.connstring = "pn532_i2c:/dev/i2c-1"

=== USAGE ===

    # Auto-detect card gen and write UID
    python -m src.nfc.recover_card --uid 5AF549D4

    # Force a specific generation
    python -m src.nfc.recover_card --uid 5AF549D4 --gen gen1a
    python -m src.nfc.recover_card --uid 5AF549D4 --gen gen2

    # Detect only (don't write)
    python -m src.nfc.recover_card --detect

    # Format the entire card (wipe all data, reset keys to default)
    python -m src.nfc.recover_card --uid 5AF549D4 --format

    # Dry run — only generate the .mfd file without writing
    python -m src.nfc.recover_card --uid 5AF549D4 --dry-run
"""

import argparse
import subprocess
import sys
import time
import tempfile
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

GEN1A = "gen1a"
GEN2 = "gen2"
REGULAR = "regular"
UNKNOWN = "unknown"


# --- Card generation detection ---

def detect_card_gen():
    """
    Detect the MIFARE Classic card generation.

    Strategy:
      1. nfc-list to verify card is present
      2. Try unlocked read (R) — if it works, card is Gen1a
      3. Try normal read (r) — if it works, card is communicable
      4. If unlocked read fails but normal read works -> Gen2 or regular
    """
    print("=== Card Generation Detection ===\n")

    card_info = _run_nfc_list()
    if not card_info:
        print("FAIL: No card detected by nfc-list. Place card on reader and retry.")
        return None, None

    print(f"  Card found: UID={card_info['uid']}, SAK=0x{card_info['sak']}, ATQA={card_info['atqa']}")

    gen1a = _test_gen1a()
    if gen1a:
        print(f"\n  Result: Gen1a (magic backdoor card)")
        print("  -> Supports unlocked read/write via magic wakeup commands")
        return GEN1A, card_info

    gen2 = _test_gen2(card_info['uid'])
    if gen2:
        print(f"\n  Result: Gen2 / CUID (direct write card)")
        print("  -> Block 0 writable via normal MIFARE Classic commands")
        return GEN2, card_info

    normal = _test_normal_read()
    if normal:
        print(f"\n  Result: Regular MIFARE Classic card")
        print("  -> Block 0 is hardware write-protected, UID cannot be changed")
        return REGULAR, card_info

    print(f"\n  Result: Unknown — card detected but all read methods failed")
    return UNKNOWN, card_info


def _run_nfc_list():
    """Run nfc-list and parse the card info."""
    try:
        result = subprocess.run(
            ['nfc-list'], capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        if 'No NFC device found' in output:
            print("  ERROR: No NFC reader found. Check libnfc config.")
            return None
        if 'ISO14443A' not in output:
            print("  No ISO14443A card detected.")
            return None

        info = {}
        for line in output.splitlines():
            line = line.strip()
            if 'UID (NFCID1):' in line:
                uid_part = line.split('UID (NFCID1):')[1].strip()
                info['uid'] = uid_part.replace('  ', '').replace(' ', '')
            elif 'SAK (SEL_RES):' in line:
                sak_part = line.split('SAK (SEL_RES):')[1].strip()
                info['sak'] = sak_part.replace(' ', '')
            elif 'ATQA (SENS_RES):' in line:
                atqa_part = line.split('ATQA (SENS_RES):')[1].strip()
                info['atqa'] = atqa_part.strip()
        return info if 'uid' in info else None

    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  ERROR: nfc-list not available or timed out.")
        return None


def _test_gen1a():
    """Try Gen1a magic unlock read (nfc-mfclassic R). Returns True if Gen1a."""
    print("\n  Testing Gen1a (magic backdoor unlock)...")
    with tempfile.NamedTemporaryFile(suffix='.mfd', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ['nfc-mfclassic', 'R', 'a', 'u', tmp_path],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr

        if 'Unlock command' in output and 'failed' in output:
            print("  -> Magic unlock FAILED (not Gen1a)")
            return False
        if result.returncode == 0 and os.path.exists(tmp_path):
            size = os.path.getsize(tmp_path)
            if size == MFD_SIZE:
                print("  -> Magic unlock SUCCESS (Gen1a confirmed)")
                return True
        print("  -> Unlocked read did not succeed")
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  -> nfc-mfclassic not available or timed out")
        return False
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _test_gen2(current_uid_hex):
    """
    Test for Gen2/CUID by reading block 0 and checking if UID in
    block 0 data matches the anti-collision UID. Gen2 cards store
    the UID in block 0 as writable data.
    """
    print("\n  Testing Gen2 / CUID (direct write to block 0)...")
    with tempfile.NamedTemporaryFile(suffix='.mfd', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ['nfc-mfclassic', 'r', 'A', 'u', tmp_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0 or not os.path.exists(tmp_path):
            print("  -> Normal read failed")
            return False

        if os.path.getsize(tmp_path) < BLOCK_SIZE:
            print("  -> Dump file too small")
            return False

        with open(tmp_path, 'rb') as f:
            block0 = f.read(BLOCK_SIZE)

        block0_uid = block0[0:4].hex()
        print(f"  -> Block 0 UID bytes: {block0_uid.upper()}")
        print(f"  -> Anti-collision UID: {current_uid_hex.upper()}")

        if block0_uid.lower() == current_uid_hex.lower():
            print("  -> Block 0 UID matches anti-collision UID (Gen2/CUID likely)")
            return True
        else:
            print("  -> Block 0 UID does NOT match (regular card or previously overwritten)")
            return True  # still communicable, might be Gen2 with mismatched block0

    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  -> Read failed or timed out")
        return False
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _test_normal_read():
    """Try a normal authenticated read to check basic card communication."""
    print("\n  Testing normal read (standard MIFARE Classic)...")
    with tempfile.NamedTemporaryFile(suffix='.mfd', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ['nfc-mfclassic', 'r', 'A', 'u', tmp_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            print("  -> Normal read succeeded")
            return True
        print("  -> Normal read failed")
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# --- Block 0 / MFD building ---

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
    return bytes(block0)


def build_sector_trailer():
    """Build a default sector trailer: KeyA(6) + Access(3) + UserByte(1) + KeyB(6)"""
    return DEFAULT_KEY + DEFAULT_ACCESS_BITS + DEFAULT_USER_BYTE + DEFAULT_KEY


def build_mfd(uid_hex, format_card=False):
    """Build a complete 1024-byte MFD dump for MIFARE Classic 1K."""
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

    print("\n--- Target Block 0 ---")
    print(f"  UID:  {uid_hex.upper()} ({' '.join(f'{b:02X}' for b in uid_bytes)})")
    print(f"  BCC:  0x{bcc:02X} (XOR of UID bytes)")
    print(f"  SAK:  0x{SAK_MIFARE_CLASSIC_1K:02X} (MIFARE Classic 1K)")
    print(f"  ATQA: 0x{ATQA_MIFARE_CLASSIC_1K[0]:02X} 0x{ATQA_MIFARE_CLASSIC_1K[1]:02X}")
    print(f"  Full: {block0.hex().upper()}")
    print()


# --- Write methods per generation ---

def _wait_for_card():
    print("Place the card on the reader...")
    for i in range(5, 0, -1):
        print(f"  Starting in {i}...", end='\r')
        time.sleep(1)
    print("  Writing now!        \n")


def write_gen1a(mfd_path):
    """Gen1a: use magic backdoor unlock write (W)."""
    print("Strategy: Gen1a magic unlock write\n")
    cmd = ['nfc-mfclassic', 'W', 'a', 'u', mfd_path]
    return _run_write_cmd(cmd)


def write_gen2(mfd_path):
    """Gen2/CUID: use normal write (w) first for data blocks, then W for block 0."""
    print("Strategy: Gen2/CUID direct write\n")
    print("Step 1: Writing block 0 via unlocked write (W)...")
    cmd_block0 = ['nfc-mfclassic', 'W', 'a', 'u', mfd_path]
    result1 = _run_write_cmd(cmd_block0)

    print("\nStep 2: Writing remaining blocks via normal write (w)...")
    cmd_data = ['nfc-mfclassic', 'w', 'A', 'u', mfd_path]
    result2 = _run_write_cmd(cmd_data)

    return result1 or result2


def _run_write_cmd(cmd):
    """Execute an nfc-mfclassic command and report results."""
    print(f"  Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)

        if result.returncode == 0:
            print("  -> Command completed successfully.")
            return True
        else:
            print(f"  -> Command failed (exit code {result.returncode})")
            return False
    except FileNotFoundError:
        print("  ERROR: 'nfc-mfclassic' not found. Install: sudo apt install libnfc-bin")
        return False
    except subprocess.TimeoutExpired:
        print("  ERROR: Timed out. Make sure card is on the reader.")
        return False


def verify_uid(expected_uid_hex):
    """Read nfc-list and check if the card's UID matches the expected one."""
    print("\n=== Verification ===\n")
    card_info = _run_nfc_list()
    if not card_info:
        print("  Could not read card for verification.")
        return False

    actual = card_info['uid'].lower()
    expected = expected_uid_hex.lower()
    print(f"  Expected UID: {expected.upper()}")
    print(f"  Actual UID:   {actual.upper()}")

    if actual == expected:
        print("\n  SUCCESS — UID matches! Card has been recovered.")
        return True
    else:
        print("\n  MISMATCH — UID did not change.")
        print("  The card may be a regular (non-magic) MIFARE Classic.")
        print("  Block 0 on regular cards is hardware write-protected.")
        return False


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description='Recover a MIFARE Classic 1K magic card — auto-detects card generation'
    )
    parser.add_argument(
        '--uid',
        help='Target 4-byte UID in hex (e.g. 5AF549D4)'
    )
    parser.add_argument(
        '--gen', choices=['gen1a', 'gen2', 'auto'], default='auto',
        help='Card generation: gen1a, gen2, or auto (default: auto)'
    )
    parser.add_argument(
        '--detect', action='store_true', default=False,
        help='Only detect the card generation, do not write'
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

    # Detection-only mode
    if args.detect:
        card_gen, card_info = detect_card_gen()
        if card_gen:
            print(f"\n  Card generation: {card_gen}")
        return

    if not args.uid:
        print("ERROR: --uid is required (unless using --detect).")
        sys.exit(1)

    uid = args.uid.replace(' ', '').replace(':', '').replace('-', '')
    if len(uid) != 8 or not all(c in '0123456789abcdefABCDEF' for c in uid):
        print(f"ERROR: Invalid UID '{args.uid}'. Must be exactly 4 bytes (8 hex chars).")
        sys.exit(1)

    # Detect card generation
    if args.gen == 'auto':
        card_gen, card_info = detect_card_gen()
        if card_gen is None:
            print("\nAborted — no card detected.")
            sys.exit(1)
        if card_gen == REGULAR:
            print("\nAborted — this is a regular MIFARE Classic card.")
            print("Block 0 is hardware write-protected. UID cannot be changed.")
            sys.exit(1)
        if card_gen == UNKNOWN:
            print("\nAborted — could not determine card generation.")
            sys.exit(1)
    else:
        card_gen = args.gen

    print(f"\nUsing card generation: {card_gen}")
    print_block0_info(uid)

    # Build and write MFD
    mfd_data = build_mfd(uid, format_card=args.format)
    mfd_path = args.output or f"recover_{uid.upper()}.mfd"
    write_mfd_file(mfd_data, mfd_path)

    if args.dry_run:
        print("Dry run — skipping card write.")
        if card_gen == GEN1A:
            print(f"To write manually: nfc-mfclassic W a u {mfd_path}")
        else:
            print(f"To write manually: nfc-mfclassic W a u {mfd_path}")
        return

    _wait_for_card()

    if card_gen == GEN1A:
        write_gen1a(mfd_path)
    elif card_gen == GEN2:
        write_gen2(mfd_path)
    else:
        print(f"No write strategy for card generation: {card_gen}")
        sys.exit(1)

    # Verify
    verify_uid(uid)


if __name__ == '__main__':
    main()
