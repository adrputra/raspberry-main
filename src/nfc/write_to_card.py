import RPi.GPIO as GPIO
import pn532.pn532 as nfc
from pn532 import *
from src.model.NFC import WriteCardUserRequest

pn532 = PN532_I2C(debug=False, reset=20, req=16)
pn532.SAM_configuration()

def write_text_to_card(block_number, text):
    """
    Writes readable text to an NFC MIFARE Classic tag.

    :param block_number: The starting block number (must avoid 4N+3 blocks).
    :param text: The text string to store.
    :return: True if successful, False otherwise.
    """
    print('Waiting for RFID/NFC card to write to...')
    while True:
        uid = pn532.read_passive_target(timeout=0.5)
        if uid:
            break

    print('Found card with UID:', [hex(i) for i in uid])

    key_a = b'\xFF\xFF\xFF\xFF\xFF\xFF'  # Default authentication key
    data = text.encode('utf-8')  # Convert text to bytes
    data = data[:16].ljust(16, b' ')  # Ensure it fits in a 16-byte block

    try:
        # Authenticate before writing
        if not pn532.mifare_classic_authenticate_block(uid, block_number, nfc.MIFARE_CMD_AUTH_A, key_a):
            print(f"Authentication failed for block {block_number}")
            return False

        # Write the data
        pn532.mifare_classic_write_block(block_number, data)

        # Verify by reading the block
        if pn532.mifare_classic_read_block(block_number) == data:
            print(f'Write successful for block {block_number}')
            return True
        else:
            print(f'Write verification failed for block {block_number}')
            return False
    except nfc.PN532Error as e:
        print("Error:", e.errmsg)
        return False
    finally:
        GPIO.cleanup()
        
def writeCardUser(request: WriteCardUserRequest):
    print('Waiting for RFID/NFC card to write to...')
    while True:
        uid = pn532.read_passive_target(timeout=0.5)
        if uid:
            break

    print('Found card with UID:', [hex(i) for i in uid])
    key_a = b'\xFF\xFF\xFF\xFF\xFF\xFF'  # Default authentication key
    
    blockUsername = [8,9]
    blockRoleID = [10,12,13,14]
    blockInstitutionID = [16, 17, 18, 20]

    # Write Username
    if len(request.username) > 16:
        for i in range(0, len(blockUsername), 1):
            basicWrite(uid=uid, key_a=key_a, blockNumber=blockUsername[i], data=request.username[:((i+1)*16)])
    else:
        basicWrite(uid=uid, key_a=key_a, blockNumber=blockUsername[0], data=request.username[:16])
        
    # Write RoleID
    for i in range(0, len(request.role_id)//16+1, 1):
        basicWrite(uid=uid, key_a=key_a, blockNumber=blockRoleID[0], data=request.role_id[:((i+1)*16)])
        
    # Write InstitutionID
    for i in range(0, len(request.institution_id)//16+1, 1):
        basicWrite(uid=uid, key_a=key_a, blockNumber=blockInstitutionID[0], data=request.institution_id[:((i+1)*16)])

def basicWrite(uid, key_a, blockNumber, data):
    try:
        # Authenticate before writing
        if not pn532.mifare_classic_authenticate_block(uid, blockNumber, nfc.MIFARE_CMD_AUTH_A, key_a):
            print(f"Authentication failed for block {blockNumber}")
            return False

        # Write the data
        pn532.mifare_classic_write_block(blockNumber, data)

        # Verify by reading the block
        if pn532.mifare_classic_read_block(blockNumber) == data:
            print(f'Write successful for block {blockNumber}')
            return True
        else:
            print(f'Write verification failed for block {blockNumber}')
            return False
    except nfc.PN532Error as e:
        print("Error:", e.errmsg)
        return False
    finally:
        GPIO.cleanup()