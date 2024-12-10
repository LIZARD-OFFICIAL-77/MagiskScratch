from flask import Flask, jsonify, request 
from googletranslate import translate

import requests
import basic_logging
import json

with open("authkey") as file:
    authkey = file.read()

app = Flask(__name__) 

access_logs = basic_logging.Logger(name="access")
system_logs = basic_logging.Logger(name="system")

def handler(json_a):
    req=json.loads(json_a)
    if req["authkey"] != authkey:
        if req["type"] == "translate":
            access_logs.info("A project used translate without an authkey. authkey is not required for this action.")
            return translate(req["text"],req["dest"])
        else:
            access_logs.warning("A project attempted to access scratchmagisk with an incorrect authkey. It's recommended to rerun the setup to generate a new authkey.")
            return "Unauthorized. This incident will be reported."
    else:
        system_logs.info(f"New request with authkey, JSON: {req}")
    if req["type"] == "translate":
        return translate(req["text"],req["dest"])
    elif req["type"] == "request":
        return requests.get(req["url"]).text

@app.route('/translate', methods=['GET']) 
def handle():
    if request.method == 'GET': 
        txt = request.args["text"]
        response = handler(txt)
        data = {"result": str(response)} 
        res = jsonify(data)
        res.headers.add('Access-Control-Allow-Origin', '*')
        print(response)
        return res
  
if __name__ == '__main__': 
    app.run(host='127.0.0.1', port=443, ssl_context=('cert/certgen.crt','cert/certgen.key')) 
