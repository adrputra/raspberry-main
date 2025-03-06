import RPi.GPIO as GPIO
import pn532.pn532 as nfc
from pn532 import PN532_I2C
import time

pn532 = PN532_I2C(debug=False, reset=20, req=16)
pn532.SAM_configuration()

def read_text_from_card(block_number):
    """
    Reads readable text from an NFC MIFARE Classic tag.

    :param block_number: List of block numbers to read.
    :return: Dictionary with UID and read values, or None if failed.
    """
    print('Waiting for RFID/NFC card to read from...')
    
    timeout_counter = 10  # Set a retry limit to avoid infinite loops
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

    key_a = b'\xFF\xFF\xFF\xFF\xFF\xFF'  # Default authentication key
    value = {}

    try:
        for block in block_number:
            # Authenticate before reading
            if not pn532.mifare_classic_authenticate_block(uid, block, nfc.MIFARE_CMD_AUTH_A, key_a):
                print(f"Authentication failed for block {block}")
                value[block] = None
                continue  # Skip this block but continue reading others

            # Read the block
            data = pn532.mifare_classic_read_block(block)
            if data:
                text = data.decode('utf-8').strip()  # Decode and remove extra spaces
                print(f"Read successful from block {block}: '{text}'")
                value[block] = text
            else:
                print(f"Failed to read block {block}")
                value[block] = None

        result = {
            "uid": uid.hex(),  # Convert UID list to tuple for dictionary compatibility
            "data": value
        }
        return result

    except nfc.PN532Error as e:
        print("Error:", e.errmsg)
        return None
