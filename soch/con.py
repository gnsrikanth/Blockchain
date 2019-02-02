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

block_chain=[]

class rsacrypt:
	def gen():
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
		return privatekey.sign(data.encode(),'')
	def verify(publickey,data,signature):
		return publickey.verify(data,signature)

class crypt:
	def hashthis(data):
		if type(data)!=str:
			return hash.new(data).hexdigest()
		else:
			return hash.new(data.encode()).hexdigest()
	def b64en(data):
		if type(data)!=str:
			return base64.b64encode(data)
		else:
			return base64.b64encode(data.encode())
	def b64de(data):
		return base64.b64decode(data)

private,public=rsacrypt.gen()
block_chain=[]

class blockchain:
    def __init__(self):
        bid=str(0)
        timestamp=str(time.time())
        data=str(0)
        publickey=(public.exportKey('PEM').decode())
        previous_block_hash=str(0)
        blockhash=str(crypt.hashthis(bid+timestamp+data+publickey+previous_block_hash))
        sign=str(private.sign(blockhash.encode(),'')[0])
        newblock={'bid':bid,
			 'timestamp':timestamp,
			 'data':data,
			 'publickey':publickey,
			 'previous_block_hash':previous_block_hash,
			 'blockhash':blockhash,
			 'sign':sign}
        block_chain.append(newblock)
        
    def create_block(data):
        bid=str(int(block_chain[-1]['bid'])+1)
        timestamp=str(time.time())
        data=str(data)
        publickey=(public.exportKey('PEM').decode())
        previous_block_hash=str(crypt.hashthis(block_chain[-1]['bid']+block_chain[-1]['timestamp']+block_chain[-1]['data']+block_chain[-1]['publickey']+block_chain[-1]['previous_block_hash']))
        blockhash=str(crypt.hashthis(bid+timestamp+data+publickey+previous_block_hash))
        sign=str(private.sign(blockhash.encode(),'')[0])
        newblock={'bid':bid,
			 'timestamp':timestamp,
			 'data':data,
			 'publickey':publickey,
			 'previous_block_hash':previous_block_hash,
			 'blockhash':blockhash,
			 'sign':sign}
        block_chain.append(newblock)
    def verify(block):
        blockhash=str(crypt.hashthis(block['bid']+block['timestamp']+block['data']+block['publickey']+block['previous_block_hash']))
        if block['blockhash']==blockhash:
            PK=RSA.importKey(block['publickey'])
            PK.verify(blockhash,(int(block['sign']),))
            return True
        else:
            return False

blockchain()

def cons():
    f=open("book.txt","r")
    ips=f.read()
    f.close()
    global block_chain   
    ips=eval(ips)
    for ip in ips :
        data=requests.get(f"http://{ip}/get")
        data=json.loads(data.text)
        if len(data) > len(block_chain):
            block_chain = data
        else: 
            pass
        
app = Flask(__name__)
@app.route('/')
def my_form():
    return ('<h3>Enter Key</h3><br/><form method="POST"><input name="key"><input type="submit"></form>')
@app.route('/get',methods=['GET'])
def get():
    return jsonify(block_chain) , 200
@app.route('/', methods=['POST'])
def my_form_post():
    cons()
    text = request.form['key']
    #text=crypt.b64en(text).decode()
    blockchain.create_block(text)
    time.sleep(2)
    return "Block Will be created",200
app.run(host = '0.0.0.0', port = 5000)
