from flask import jsonify

def ResponseWrapper(message=None, data=None, status_code=200):
    response_body = {
        "code": status_code,
        "message": message,
        "data": data,
    }
    return jsonify(response_body), status_code
