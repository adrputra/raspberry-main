from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
from src.config.config import config
from src.route.route import routes
from src.nfc.attendance import attendance

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

routes.socketio = socketio
app.register_blueprint(routes)

def start_nfc_scanner():
    print("Starting NFC scanner...")
    attendance(socketio)

if __name__ == '__main__':
    socketio.start_background_task(start_nfc_scanner)

    socketio.run(app, host=config["server"]["host"], port=config["server"]["port"], debug=config["server"]["debug"])