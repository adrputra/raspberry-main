from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
from src.config.config import config
from src.route.route import routes

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

routes.socketio = socketio
app.register_blueprint(routes)

if __name__ == '__main__':
    # socketio.start_background_task(nfc_listener)
    socketio.run(app, host=config["server"]["host"], port=config["server"]["port"], debug=config["server"]["debug"])