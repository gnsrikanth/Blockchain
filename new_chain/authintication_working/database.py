import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
import time
data=[]
app = Flask(__name__)
@app.route('/')
def my_form():
    return ('Welcome to the Database'),200

@app.route('/get',methods=['GET'])
def get():
    return jsonify(data) , 200

@app.route('/', methods=['POST'])
def my_form_post():
    text = request.form['key']
    data.append(text)
    time.sleep(2)
    return "okay",200
app.run(host = '0.0.0.0', port = 5002) 