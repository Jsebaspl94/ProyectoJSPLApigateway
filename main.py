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

@app.before_request
def middleware():

    urlCliente = request.path
    metodoCliente = request.method


    if (urlCliente == "/login"):
        pass

    else:

        verify_jwt_in_request()

        infoToken = get_jwt_identity()
        idRol = infoToken["rol"]["_id"]

        print("url antes:", urlCliente)
        urlCliente = transformarUrl(urlCliente)

        print("url ahora:", urlCliente)

        urlValidarPermiso = dataConfig["url-backend-security"] + "/permisos-rol/validar-permiso/rol/"+idRol

        headers = {"Content-Type": "application/json"}
        bodyRequest = {
            "url": urlCliente,
            "metodo": metodoCliente
        }

        responseValidarPermiso = requests.get(urlValidarPermiso, json=bodyRequest, headers=headers)
        print("Status code del servicio validar permiso", responseValidarPermiso)

        if (responseValidarPermiso.status_code == 200):

            print("El cliente si tiene permisos")
            pass
        else:
            return{"mensaje": "Permiso Denegado"}, 401

def transformarUrl(urlCliente):

    listadoPalabras= urlCliente.split("/")

    for palabra in listadoPalabras:
        if re.search('\\d', palabra):
            urlCliente = urlCliente.replace(palabra, "?")

    return urlCliente


@app.route("/login", methods=['POST'])
def validarUsuario():
    print("Entro a validar usuario")
    url = dataConfig["url-backend-security"] + "/usuarios/validar-usuario"

    headers = {"Content-Type": "application/json"}

    bodyRequest = request.get_json()

    response = requests.post(url, json=bodyRequest, headers=headers)

    if (response.status_code == 200):
        print("El usuario se valido correctamente")
        infoUsuario = response.json()

        tiempoDelToken = datetime.timedelta(seconds=60*60)
        newToken = create_access_token(identity=infoUsuario,expires_delta=tiempoDelToken)

        return {"token" : newToken}
    else:
        return {"mensaje":"Usuario y contraseña Erroneos"}, 401


@app.route("/candidato", methods=['POST'])
def crearCandidato():

    url = dataConfig["url-backend-registraduria"] + "/candidato"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()

@app.route("/candidato/<string:idCandidato>", methods=['GET'])
def buscarCandidato(idCandidato):
    url = dataConfig["url-backend-registraduria"] + "/candidato/" + idCandidato
    headers = {"Content-Type": "application/json"}


    response = requests.get(url, headers=headers)

    return response.json()





#ccccccccccccccccccccc




















@app.route("/candidato", methods=['GET'])
def buscarTodosLosCandidatos():
    url = dataConfig["url-backend-registraduria"] + "/candidato"
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/candidato", methods=['PUT'])
def actualizarCandidato():

    url = dataConfig["url-backend-registraduria"] + "/candidato"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.put(url, json=body, headers=headers)

    return response.json()



#Ruta para relación uno a muchos
@app.route("/candidato/<string:idCandidato>/partido/<string:idPartido>", methods=['PUT'])
def AsignarPartidoCandidato(idCandidato, idPartido):
    url = dataConfig["url-backend-registraduria"] + "/candidato/" + idCandidato + "/partido/" + idPartido
    headers = {"Content-Type": "application/json"}

    response = requests.put(url, headers=headers)

    return response.json()



@app.route("/candidato/<string:idCandidato>", methods=['DELETE'])
def eliminarCandidato(idCandidato):
    url = dataConfig["url-backend-registraduria"] + "/candidato/" + idCandidato
    headers = {"Content-Type": "application/json"}

    response = requests.delete(url, headers=headers)

    return response.json()





#Registro de endpoints para las funcionalidades de Mesa
@app.route("/mesa", methods=['POST'])
def crearMesa():
    url = dataConfig["url-backend-registraduria"] + "/mesa"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()


@app.route("/mesa/<string:idMesa>", methods=['GET'])
def buscarMesa(idMesa):
    url = dataConfig["url-backend-registraduria"] + "/mesa/" + idMesa
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/mesa", methods=['GET'])
def buscarTodasLasMesas():
    url = dataConfig["url-backend-registraduria"] + "/mesa"
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/mesa", methods=['PUT'])
def actualizarMesa():
    url = dataConfig["url-backend-registraduria"] + "/mesa"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.put(url, json=body, headers=headers)

    return response.json()

@app.route("/mesa/<string:idMesa>", methods=['DELETE'])
def eliminarMesa(idMesa):
    url = dataConfig["url-backend-registraduria"] + "/mesa/" + idMesa
    headers = {"Content-Type": "application/json"}

    response = requests.delete(url, headers=headers)

    return response.json()


#Registro de endpoints para las funcionalidades de Partido
@app.route("/partido", methods=['POST'])
def crearPartido():
    url = dataConfig["url-backend-registraduria"] + "/partido"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()

@app.route("/partido/<string:idPartido>", methods=['GET'])
def buscarPartido(idPartido):
    url = dataConfig["url-backend-registraduria"] + "/partido/" + idPartido
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/partido", methods=['GET'])
def buscarTodosLosPartidos():
    url = dataConfig["url-backend-registraduria"] + "/partido"
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/partido", methods=['PUT'])
def actualizarPartido():
    url = dataConfig["url-backend-registraduria"] + "/partido"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.put(url, json=body, headers=headers)

    return response.json()

@app.route("/partido/<string:idPartido>", methods=['DELETE'])
def eliminarPartido(idPartido):
    url = dataConfig["url-backend-registraduria"] + "/partido/" + idPartido
    headers = {"Content-Type": "application/json"}

    response = requests.delete(url, headers=headers)

    return response.json()


#Registro de endpoints para las funcionalidades de Resultados
@app.route("/resultado/mesa/<string:idMesa>/candidato/<string:idCandidato>", methods=['POST'])
def crearResultado(idMesa, idCandidato):
    url = dataConfig["url-backend-registraduria"] + "/resultado/mesa/" + idMesa + "/candidato/" + idCandidato
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()
@app.route("/resultado/<string:idResultado>", methods=['GET'])
def buscarResultado(idResultado):
    url = dataConfig["url-backend-registraduria"] + "/resultado/" + idResultado
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/resultado", methods=['GET'])
def buscarTodosLosResultados():
    url = dataConfig["url-backend-registraduria"] + "/resultado"
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()


@app.route("/resultado", methods=['PUT'])
def actualizarResultado():
    url = dataConfig["url-backend-registraduria"] + "/resultado"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.put(url, json=body, headers=headers)

    return response.json()

@app.route("/resultado/<string:idResultado>", methods=['DELETE'])
def eliminarResultado(idResultado):
    url = dataConfig["url-backend-registraduria"] + "/resultado/" + idResultado
    headers = {"Content-Type": "application/json"}

    response = requests.delete(url, headers=headers)

    return response.json()










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

