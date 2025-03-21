from flask import Flask, render_template
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

@app.route('/nfc-status')
def nfc_status():
    return render_template('nfc_status.html')

def start_nfc_scanner():
    try:
        socketio.emit('nfc_status', {'message': 'NFC scanner started'})
        print("Starting NFC scanner...")
        attendance(socketio)
    except Exception as e:
        print(str(e))

if __name__ == '__main__':
    # Uncomment this line to start the NFC scanner in Background
    # socketio.start_background_task(start_nfc_scanner)
    
    socketio.run(app, host=config["server"]["host"], port=config["server"]["port"], debug=config["server"]["debug"])
