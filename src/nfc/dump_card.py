"""
Full MIFARE Classic 1K Card Dump Tool

Reads ALL 64 blocks of a MIFARE Classic 1K card, attempting multiple
common keys for authentication. Displays raw hex data, decoded ASCII,
block type annotations, and a copyable summary for writing back.

Usage (from project root):
    python -m src.nfc.dump_card

    # Save dump to file
    python -m src.nfc.dump_card --output dump.txt

    # JSON output (for programmatic use)
    python -m src.nfc.dump_card --json
"""

import RPi.GPIO as GPIO
import pn532.pn532 as nfc
from pn532 import PN532_I2C
import time
import json
import argparse
import sys

pn532 = PN532_I2C(debug=False, reset=20, req=16)
pn532.SAM_configuration()

MIFARE_1K_BLOCKS = 64
MIFARE_1K_SECTORS = 16
BLOCK_SIZE = 16

COMMON_KEYS = [
    b'\xFF\xFF\xFF\xFF\xFF\xFF',  # Factory default
    b'\xA0\xA1\xA2\xA3\xA4\xA5',  # MAD key (MIFARE Application Directory)
    b'\xD3\xF7\xD3\xF7\xD3\xF7',  # NFC Forum key
    b'\x00\x00\x00\x00\x00\x00',  # All zeros
    b'\xB0\xB1\xB2\xB3\xB4\xB5',  # Common custom key
    b'\x4D\x3A\x99\xC3\x51\xDD',  # Common transport key
    b'\x1A\x98\x2C\x7E\x45\x9A',  # Common transport key
    b'\xAA\xBB\xCC\xDD\xEE\xFF',  # Sequential key
    b'\x71\x4C\x5C\x88\x6E\x97',  # Philips/NXP
    b'\x58\x7E\xE5\xF9\x35\x0F',  # Common
    b'\xA0\xB0\xC0\xD0\xE0\xF0',  # Common
    b'\x53\x3C\xB6\xC7\x23\xF6',  # Common
    b'\x8F\xD0\xA4\xF2\x56\xE9',  # Common
]


def get_sector_for_block(block):
    return block // 4


def is_sector_trailer(block):
    return (block + 1) % 4 == 0


def get_block_type(block):
    if block == 0:
        return "MANUFACTURER"
    elif is_sector_trailer(block):
        return "SECTOR_TRAILER"
    else:
        return "DATA"


def decode_block0(data):
    """Parse manufacturer block (block 0)."""
    uid = data[0:4]
    bcc = data[4]
    sak = data[5]
    atqa = data[6:8]
    manufacturer = data[8:16]
    expected_bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]

    return {
        "uid": uid.hex().upper(),
        "bcc": f"0x{bcc:02X}",
        "bcc_valid": bcc == expected_bcc,
        "sak": f"0x{sak:02X}",
        "atqa": atqa.hex().upper(),
        "manufacturer": manufacturer.hex().upper(),
    }


def decode_sector_trailer(data):
    """Parse sector trailer block."""
    key_a = data[0:6]
    access_bits = data[6:10]
    key_b = data[10:16]

    return {
        "key_a": key_a.hex().upper(),
        "access_bits": access_bits.hex().upper(),
        "key_b": key_b.hex().upper(),
    }


def to_ascii(data):
    """Convert bytes to printable ASCII, replacing non-printable chars with '.'"""
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


def reselect_card(retries=3):
    """Re-select the card after a failed auth or communication error."""
    for _ in range(retries):
        time.sleep(0.2)
        try:
            uid = pn532.read_passive_target(timeout=1)
            if uid:
                return uid
        except RuntimeError:
            time.sleep(0.3)
    return None


def try_authenticate(uid, block, keys=None):
    """Try multiple keys to authenticate a block. Returns the key that worked or None."""
    if keys is None:
        keys = COMMON_KEYS

    for key in keys:
        # Try Key A
        try:
            result = pn532.mifare_classic_authenticate_block(
                uid, block, nfc.MIFARE_CMD_AUTH_A, key
            )
            if result:
                return key, "A"
        except nfc.PN532Error:
            pass
        except RuntimeError:
            pass

        uid_retry = reselect_card()
        if not uid_retry:
            return None, None
        uid = uid_retry

        # Try Key B
        try:
            result = pn532.mifare_classic_authenticate_block(
                uid, block, nfc.MIFARE_CMD_AUTH_B, key
            )
            if result:
                return key, "B"
        except nfc.PN532Error:
            pass
        except RuntimeError:
            pass

        uid_retry = reselect_card()
        if not uid_retry:
            return None, None
        uid = uid_retry

    return None, None


def dump_card():
    """Read all 64 blocks from a MIFARE Classic 1K card."""
    print("Waiting for card (place only ONE card on the reader)...")
    uid = None

    for attempt in range(10):
        time.sleep(1)
        try:
            uid = pn532.read_passive_target(timeout=5)
            if uid:
                break
        except RuntimeError as e:
            if 'More than one card' in str(e):
                print("  Multiple cards detected — remove extra cards!")
            else:
                print(f"  Communication error, retrying... ({e})")
            time.sleep(1)

    if not uid:
        print("No card detected.")
        return None

    print(f"Card detected — UID: {uid.hex().upper()}\n")

    blocks = []
    current_sector_key = None
    current_sector = -1
    key_type = None

    for block in range(MIFARE_1K_BLOCKS):
        sector = get_sector_for_block(block)
        block_type = get_block_type(block)

        # Authenticate at the start of each new sector
        if sector != current_sector:
            current_sector = sector
            first_block_of_sector = sector * 4

            # Re-select card before authenticating a new sector
            uid_fresh = reselect_card()
            if uid_fresh:
                uid = uid_fresh

            key, key_type = try_authenticate(uid, first_block_of_sector)
            current_sector_key = key

        block_data = {
            "block": block,
            "sector": sector,
            "type": block_type,
            "hex": None,
            "ascii": None,
            "key_used": None,
            "key_type": None,
            "error": None,
        }

        if current_sector_key is None:
            block_data["error"] = "AUTH_FAILED"
            blocks.append(block_data)
            continue

        # Try reading with retries for I2C communication errors
        read_success = False
        for read_attempt in range(3):
            try:
                data = pn532.mifare_classic_read_block(block)
                if data:
                    block_data["hex"] = data.hex().upper()
                    block_data["ascii"] = to_ascii(data)
                    block_data["key_used"] = current_sector_key.hex().upper()
                    block_data["key_type"] = key_type

                    if block == 0:
                        block_data["parsed"] = decode_block0(data)
                    elif is_sector_trailer(block):
                        block_data["parsed"] = decode_sector_trailer(data)
                    read_success = True
                    break
                else:
                    block_data["error"] = "READ_FAILED"
                    break
            except nfc.PN532Error as e:
                block_data["error"] = e.errmsg
                break
            except RuntimeError as e:
                if read_attempt < 2:
                    time.sleep(0.2)
                    uid_fresh = reselect_card()
                    if uid_fresh:
                        uid = uid_fresh
                    # Re-authenticate for this sector
                    try:
                        pn532.mifare_classic_authenticate_block(
                            uid, block, nfc.MIFARE_CMD_AUTH_A, current_sector_key
                        )
                    except (nfc.PN532Error, RuntimeError):
                        pass
                else:
                    block_data["error"] = f"COMM_ERROR: {e}"

        blocks.append(block_data)

    return {"uid": uid.hex().upper(), "blocks": blocks}


def print_dump(dump_data):
    """Pretty-print the full card dump."""
    uid = dump_data["uid"]
    blocks = dump_data["blocks"]

    print("=" * 80)
    print(f"  MIFARE Classic 1K — Full Dump")
    print(f"  UID: {uid}")
    print("=" * 80)

    print(f"\n{'Block':>5} | {'Sector':>6} | {'Type':<16} | {'Hex Data':<34} | {'ASCII':<18} | {'Key'}")
    print("-" * 120)

    for b in blocks:
        block = b["block"]
        sector = b["sector"]
        btype = b["type"]
        hex_data = b["hex"] or "?? " * 16
        ascii_data = b["ascii"] or ""
        error = b["error"]

        if error:
            line = f"{block:>5} | {sector:>6} | {btype:<16} | {'[' + error + ']':<34} | {'':<18} |"
        else:
            hex_spaced = ' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
            key_info = ""
            if b["key_used"]:
                key_info = f"Key{b['key_type']}:{b['key_used']}"
            line = f"{block:>5} | {sector:>6} | {btype:<16} | {hex_spaced:<48} | {ascii_data:<18} | {key_info}"

        print(line)

        if is_sector_trailer(block):
            print("-" * 120)

    # Block 0 parsed info
    block0 = blocks[0]
    if block0.get("parsed"):
        p = block0["parsed"]
        print(f"\n--- Block 0 (Manufacturer) ---")
        print(f"  UID:  {p['uid']}")
        print(f"  BCC:  {p['bcc']} ({'valid' if p['bcc_valid'] else 'INVALID'})")
        print(f"  SAK:  {p['sak']}")
        print(f"  ATQA: {p['atqa']}")
        print(f"  Mfr:  {p['manufacturer']}")

    # Sector trailer summary
    print(f"\n--- Sector Keys ---")
    print(f"{'Sector':>6} | {'Key A':<14} | {'Access Bits':<10} | {'Key B':<14}")
    print("-" * 55)
    for b in blocks:
        if b["type"] == "SECTOR_TRAILER" and b.get("parsed"):
            p = b["parsed"]
            print(f"{b['sector']:>6} | {p['key_a']:<14} | {p['access_bits']:<10} | {p['key_b']:<14}")
        elif b["type"] == "SECTOR_TRAILER":
            print(f"{b['sector']:>6} | {'?':<14} | {'?':<10} | {'?':<14}")


def print_copyable(dump_data):
    """Print a copyable format for writing the card back."""
    blocks = dump_data["blocks"]

    print(f"\n{'=' * 80}")
    print("  COPYABLE FORMAT — use these hex values to write back to a card")
    print(f"{'=' * 80}")
    print(f"  UID: {dump_data['uid']}")
    print()
    print("  Format per line: BLOCK_NUMBER:HEX_DATA")
    print("  (16 bytes = 32 hex chars per block)")
    print()

    for b in blocks:
        if b["hex"]:
            marker = ""
            if b["type"] == "MANUFACTURER":
                marker = "  # UID + manufacturer"
            elif b["type"] == "SECTOR_TRAILER":
                marker = "  # KeyA + Access + KeyB"
            print(f"  {b['block']:02d}:{b['hex']}{marker}")
        else:
            error = b.get("error", "UNREADABLE")
            print(f"  {b['block']:02d}:{'XX' * 16}  # {error}")


def main():
    parser = argparse.ArgumentParser(description='Dump all blocks of a MIFARE Classic 1K card')
    parser.add_argument('--output', '-o', default=None, help='Save output to a text file')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    dump_data = dump_card()
    if not dump_data:
        sys.exit(1)

    if args.json:
        output = json.dumps(dump_data, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"JSON dump saved to: {args.output}")
        else:
            print(output)
    else:
        print_dump(dump_data)
        print_copyable(dump_data)

        if args.output:
            import io
            buf = io.StringIO()
            orig_stdout = sys.stdout
            sys.stdout = buf
            print_dump(dump_data)
            print_copyable(dump_data)
            sys.stdout = orig_stdout
            with open(args.output, 'w') as f:
                f.write(buf.getvalue())
            print(f"\nDump saved to: {args.output}")


if __name__ == '__main__':
    main()
