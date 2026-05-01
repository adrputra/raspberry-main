import RPi.GPIO as GPIO
import pn532.pn532 as nfc
from pn532 import PN532_I2C
import time

pn532 = PN532_I2C(debug=False, reset=20, req=16)
pn532.SAM_configuration()

def _is_sector_trailer(block):
    """Returns True if block is a sector trailer (read-only keys/access bits)."""
    return (block + 1) % 4 == 0

def _is_manufacturer_block(block):
    """Returns True if block is the manufacturer block (block 0, read-only)."""
    return block == 0

def read_text_from_card(block_number):
    """
    Reads readable text from an NFC MIFARE Classic tag.

    :param block_number: List of block numbers to read.
    :return: Dictionary with UID and read values, or None if failed.

    Notes on MIFARE Classic 1K block layout (Sector 0):
      Block 0 - Manufacturer block (UID + manufacturer data, hardware read-only)
      Block 1 - Data block
      Block 2 - Data block
      Block 3 - Sector trailer (keys + access bits, not user data)
    """
    print('Waiting for RFID/NFC card to read from...')
    
    timeout_counter = 10
    while timeout_counter > 0:
        time.sleep(2)
        uid = pn532.read_passive_target(timeout=5)
        if uid:
            break
        timeout_counter -= 1

    if not uid:
        print("No card detected after multiple attempts.")
        return None

    print('Found card with UID:', uid.hex())

    key_a = b'\xFF\xFF\xFF\xFF\xFF\xFF'
    value = {}

    try:
        for block in block_number:
            if _is_sector_trailer(block):
                print(f"Skipping block {block} (sector trailer — stores keys/access bits, not data)")
                value[block] = None
                continue

            if _is_manufacturer_block(block):
                print(f"Skipping block {block} (manufacturer block — hardware read-only)")
                value[block] = None
                continue

            if not pn532.mifare_classic_authenticate_block(uid, block, nfc.MIFARE_CMD_AUTH_A, key_a):
                print(f"Authentication failed for block {block}")
                value[block] = None
                continue

            data = pn532.mifare_classic_read_block(block)
            if data:
                text = data.decode('utf-8').strip()
                print(f"Read successful from block {block}: '{text}'")
                value[block] = text
            else:
                print(f"Failed to read block {block}")
                value[block] = None

        result = {
            "uid": uid.hex(),
            "data": value
        }
        return result

    except nfc.PN532Error as e:
        print("Error:", e.errmsg)
        return None
