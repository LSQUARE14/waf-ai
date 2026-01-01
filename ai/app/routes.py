from flask import Blueprint, jsonify, request
from app.services.xgboost_detector import XGBoostDetector, preprocess_payloads
from app.services.mcp_client import run_mcp_client
import threading
import json
from app.services.util import dumps_request
import os

main = Blueprint('main', __name__)

@main.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@main.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def ai_filter(path):
    print(dumps_request())

@main.route('/api/detect', methods=['POST'])
def malicious_payload_detect():
    data = request.json
    result = data["request_data"].split("HTTP request JSON: ")[-1]
    result = json.loads(result)
    value_list = []
    if "headers" in result:
        headers = result["headers"]
        for key, value in headers.items():
            headers[key] = preprocess_payloads([value])[0]
            value_list.append(key + ": " + headers[key])
    if "body" in result:
        body = result["body"]
        for key, value in body.items():
            body[key] = preprocess_payloads([value])[0]
            value_list.append(key + ": " + body[key])
    detector = XGBoostDetector("/ml_detector/app/resources/xgboost_httpParams.json")
    is_safe = detector.predict(value_list)
    result = data["request_data"]
    if not is_safe:
        print(type(result))
        threading.Thread(target=run_mcp_client, args=(result,), daemon=True).start()
    return jsonify({"is_safe": is_safe}), 200 if is_safe else 403