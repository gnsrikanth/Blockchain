import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64
import time


import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse

class rsa:
	def rsakeys():
		length=1024
		privatekey = RSA.generate(length, Random.new().read)
		publickey = privatekey.publickey()
		return privatekey, publickey
	def encrypt(rsa_publickey,plain_text):
		cipher_text=rsa_publickey.encrypt(plain_text,32)[0]
		b64cipher=base64.b64encode(cipher_text)
		return b64cipher
	def decrypt(b64cipher, rsa_privatekey):
		decoded_ciphertext = base64.b64decode(b64cipher)
		plaintext = rsa_privatekey.decrypt(decoded_ciphertext)
		return plaintext
	def exportkeys(publickey,privatekey,private_file,public_file):
		f=open(private_file,"w")
		f.write((privatekey.exportKey('PEM')).decode())
		f.close()
		f=open(public_file,"w")
		f.write((publickey.exportKey('PEM')).decode())
		f.close()
	def getkeys(publickey_file,privatekey_file):
		f=open(privatekey_file,"r")
		privatekey=RSA.importKey(f.read())
		f.close()
		f=open(publickey_file,"r")
		publickey=RSA.importKey(f.read())
		f.close()
		return privatekey,publickey
	def sign(privatekey,data):
		#datahash=hash.new(data).digest()
		return privatekey.sign(data,'')
	def verify(publickey,data,signature):
		return publickey.verify(data,signature)

class crypt:
    def b64en(data):
        return base64.b64encode(data)
    def b64de(data):
        return base64.b64decode(data)
    def hashdata(data):
        return hash.new(data.encode()).hexdigest()


my_privatekey,my_publickey=rsa.rsakeys()
block_chain=[]

class Blockchain:
	#Our Block Chain
    def create_block(data):
            hashthis=(crypt.hashdata(str(len(block_chain)+1)+str(data)+str(time.time())+str(my_publickey)))
            blockdata={'id':str(len(block_chain)+1),
            'data':str(data),
            'timestamp':str(time.time()),
            'hash':hashthis,
            'publickey':(crypt.b64en(my_publickey.exportKey('PEM'))).decode(),
            'sign':rsa.sign(my_privatekey,hashthis.encode())}
            return blockdata
    #Our block making
    def make_block(blockdata):
            my_pub=RSA.importKey(crypt.b64de(blockdata['publickey'].encode()))
            if rsa.verify(my_pub,((blockdata['hash']).encode()),(blockdata['sign'])) == True:
                block_chain.append(blockdata)
                print("OK")
            else:
                print(blockdata['hash'])
                print(type(blockdata['hash']))
                print("Not Valid")

#Flask From here
app = Flask(__name__)
@app.route('/get_chain', methods = ['GET'])
def mine_chain():
	return jsonify(block_chain),200
@app.route('/get_public', methods = ['GET'])
def get_public():
	return (crypt.b64en(my_publickey.exportKey('PEM'))).decode(),200
@app.route('/')
def my_form():
    return ('<h3>Enter Key</h3><br/><form method="POST"><input name="key"><input type="submit"></form>')

@app.route('/', methods=['POST'])
def my_form_post():
    text = request.form['key']
    ch=Blockchain.create_block(text)
    Blockchain.make_block(ch)
    time.sleep(2)
    return "Block Will be created",200
app.run(host = '0.0.0.0', port = 5000)
