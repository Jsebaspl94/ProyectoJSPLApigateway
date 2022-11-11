from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

import json
import requests
import datetime

from waitress import serve
import datetime
import requests
import re

app=Flask(__name__)

app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que se conveniente
jwt = JWTManager(app)

cors = CORS(app)

@app.route("/login", methods=['POST'])
def validarUsuario():

    url = dataConfig["url-backend-security"] + "/usuarios/validar-usuario"

    headers = {
        "Content-Type": "application/json"
    }

    bodyRequest = request.get_json()

    response = requests.post(url, json=bodyRequest, headers=headers)

    if (response.status_code == 200):
        print("El usuario se valido correctamente")
        infoUsuario = response.json()

        tiempoDelToken = datetime.timedelta(seconds=60)
        newToken = create_access_token(identity=infoUsuario,expires_delta=tiempoDelToken)

        return {"token" : newToken}
    else:
        return {"mensaje":"Usuario y contraseña Erroneos"}, 401




#@app.route("/",methods=['GET'])
#def test():
    #json = {}
    #json["message"]="Server running ..."
    #return jsonify(json)
def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data
if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])

