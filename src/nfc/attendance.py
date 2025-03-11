import RPi.GPIO as GPIO
import pn532.pn532 as nfc
from pn532 import PN532_I2C
import time
from src.model.NFC import UserCheckInOutRequest
import requests

# Initialize NFC reader
pn532 = PN532_I2C(debug=False, reset=20, req=16)
pn532.SAM_configuration()

def attendance(socketio=None):
    print('Waiting for RFID/NFC card to read from...')
    
    while True:  # Infinite loop to keep scanning
        try:
            time.sleep(2)
            uid = pn532.read_passive_target(timeout=5)

            if not uid:
                print("No card detected, retrying...")
                continue  # Restart loop to wait for the next scan

            socketio.emit('nfc_status', {'status': 'Scanning ...'})
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
                    text = data.decode('utf-8').replace('\x00', '').strip()  # Decode and remove extra spaces
                    print(f"Read successful from block {block}: '{text}'")
                    value[block] = text
                else:
                    print(f"Failed to read block {block}")
                    value[block] = None

            username = value[blockUsername[0]] + value[blockUsername[1]]
            roleID = value[blockRoleID[0]] + value[blockRoleID[1]] + value[blockRoleID[2]] + value[blockRoleID[3]]

            url = "http://192.168.81.77:8002/api/checkinout-rfid"
            request = {
                "username": username,
                "source_in": "Raspi RFID",
                "source_out": "Raspi RFID"
            }

            headers = {
                "Content-Type": "application/json",
                "app-role-id": roleID,
            }

            socketio.emit('nfc_status', {'status': f'Card scanned with UID: {uid.hex()}'})
            print(f'REQUEST: {url, headers, request}') 
            
            socketio.emit('nfc_message', {'message': 'Recording attendance...'})

            response = requests.post(url, json=request, headers=headers)

            if response.status_code == 200:
                socketio.emit('nfc_message', {'message': 'Attendance recorded successfully'})
                print(response.json().get("message", "Attendance recorded successfully"))
            else:
                socketio.emit('nfc_message', {'message': 'Failed to record attendance'})
                print(f"Failed to record attendance. Status code: {response.status_code}, Response: {response.text}")

        except nfc.PN532Error as e:
            print("Error:", e.errmsg)

        except requests.RequestException as e:
            socketio.emit('nfc_message', {'message': 'Network error'})
            print(f"Network error: {e}")

        except KeyboardInterrupt:
            print("\nShutting down NFC scanner...")
            GPIO.cleanup()
            break  # Exit the loop safely
        
        finally:
            time.sleep(2)
            socketio.emit('nfc_status', {'status': 'Waiting for NFC card...'})
            socketio.emit('nfc_message', {'message': '...'})
            GPIO.cleanup()

if __name__ == "__main__":
    attendance()
