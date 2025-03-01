from flask import Blueprint, jsonify, request
from globalVariable import readMode
from src.utils.response import ResponseWrapper
import src.services.service as service

routes = Blueprint("r", __name__)

socketio = None

@routes.route("/ping", methods=["GET"])
def Ping():
    return ResponseWrapper(message="Pong", status_code=200, data=None)
    
@routes.route("/read-card-block", methods=["POST"])
def ReadCardBlock():
    result = service.NFCListener(request)
    return ResponseWrapper(message="Read Card Success", status_code=200, data=result)

@routes.route("/write-card-block", methods=["POST"])
def WriteCardBlock():
    result = service.NFCWriter(request)
    return ResponseWrapper(message="Write Card Success", status_code=200, data=result)

@routes.route("/write-card-user", methods=["POST"])
def WriteCardUser():
    result = service.NFCWriteUser(request)
    return ResponseWrapper(message="Write Card User Success", status_code=200, data=result)