import time
from globalVariable import readMode
from src.model.NFC import ReadCardRequest, WriteCardRequest
from src.nfc.read_card import read_text_from_card
from src.nfc.write_to_card import write_text_to_card

def NFCListener(request):
    try:
        request = ReadCardRequest(**request.json)
        return read_text_from_card(request.blockNumber)
    except Exception as e:
        return str(e)
    
def NFCWriter(request):
    try:
        request = WriteCardRequest(**request.json)
        result = write_text_to_card(request.blockNumber, request.data)
        if result:
            return "Write Card Success"
        else:
            return "Write Card Failed"
    except Exception as e:
        return str(e)

def NFCWriteUser(request):
    try:    
        request = WriteCardRequest(**request.json)
        result = write_text_to_card(request.blockNumber, request.data)
        if result:
            return "Write Card Success"
        else:
            return "Write Card Failed"
    except Exception as e:
        return str(e)