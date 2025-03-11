from flask import Flask, render_template
from flask_cors import CORS
from flask_socketio import SocketIO
from src.config.config import config
from src.route.route import routes
from src.nfc.attendance import attendance
import logging
import time

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

routes.socketio = socketio
app.register_blueprint(routes)

@app.route('/nfc-status')
def nfc_status():
    return render_template('nfc_status.html')

def start_nfc_scanner():
    while True:
        try:
            socketio.emit('nfc_status', {'message': 'NFC scanner started'})
            print("Starting NFC scanner...")
            attendance(socketio)
        except Exception as e:
            logging.error(f"Error in NFC scanner: {e}")
            time.sleep(5)  # Wait before restarting the scanner

if __name__ == '__main__':
    while True:
        try:
            socketio.start_background_task(start_nfc_scanner)
            socketio.run(app, host=config["server"]["host"], port=config["server"]["port"], debug=config["server"]["debug"])
        except Exception as e:
            logging.error(f"Error starting the application: {e}")
            time.sleep(5)  # Wait before restarting the application
