import RPi.GPIO as GPIO
import pn532.pn532 as nfc
from pn532 import PN532_I2C
import time
from src.model.NFC import UserCheckInOutRequest
import requests

# Initialize NFC reader
pn532 = PN532_I2C(debug=False, reset=20, req=16)
pn532.SAM_configuration()

def attendance():
    print('Waiting for RFID/NFC card to read from...')
    
    while True:  # Infinite loop to keep scanning
        try:
            time.sleep(2)
            uid = pn532.read_passive_target(timeout=5)

            if not uid:
                print("No card detected, retrying...")
                continue  # Restart loop to wait for the next scan

            print('Found card with UID:', uid.hex())

            key_a = b'\xFF\xFF\xFF\xFF\xFF\xFF'  # Default authentication key
            value = {}

            blockUsername = [8,9]
            blockRoleID = [10,12,13,14]
            blockInstitutionID = [16, 17, 18, 20]

            block_number = blockUsername + blockRoleID + blockInstitutionID

            for block in block_number:
                if not pn532.mifare_classic_authenticate_block(uid, block, nfc.MIFARE_CMD_AUTH_A, key_a):
                    print(f"Authentication failed for block {block}")
                    value[block] = None
                    continue  

                data = pn532.mifare_classic_read_block(block)
                if data:
                    text = data.decode('utf-8').strip()  # Decode and remove extra spaces
                    print(f"Read successful from block {block}: '{text}'")
                    value[block] = text
                else:
                    print(f"Failed to read block {block}")
                    value[block] = None

            username = value[blockUsername[0]] + value[blockUsername[1]]
            roleID = value[blockRoleID[0]] + value[blockRoleID[1]] + value[blockRoleID[2]] + value[blockRoleID[3]]

            url = "https://bpkp-portal.eventarry.com/api/checkinout-rfid"
            data = UserCheckInOutRequest(username=username, source_in="Raspi RFID", source_out="Raspi RFID")

            headers = {
                "Content-Type": "application/json",
                "app-role-id": roleID,
            }

            print(f'REQUEST: {url, headers, data}')

            response = requests.post(url, json=data, headers=headers)

            if response.status_code == 200:
                print(response.json().get("message", "Attendance recorded successfully"))
            else:
                print(f"Failed to record attendance. Status code: {response.status_code}, Response: {response.text}")

        except nfc.PN532Error as e:
            print("Error:", e.errmsg)

        except requests.RequestException as e:
            print(f"Network error: {e}")

        except KeyboardInterrupt:
            print("\nShutting down NFC scanner...")
            GPIO.cleanup()
            break  # Exit the loop safely

if __name__ == "__main__":
    attendance()
