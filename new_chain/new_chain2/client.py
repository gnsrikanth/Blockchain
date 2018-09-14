import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64
import time
import json
import requests

class ersa:
	def gen():
		length=1024
		privatekey=RSA.generate(length,Random.new().read)
		publickey=privatekey.publickey()
		return privatekey,publickey
	#def encrypt():
		
	#def decrypt():
		
	def sign(privatekey,data):
		if type(data)!=str:
			return privatekey.sign(data,'')
		else:
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

private,public=ersa.gen()
pk=str(((public.exportKey('PEM'))).decode())
requests.post('http://127.0.0.1:5000', data = {'key':pk})

# GET BLOCKCHAIN
blockchain=requests.get("http://127.0.0.1:5000/get")
blockchain=blockchain.text
blockchain=json.loads(blockchain)

#Find my id CID
for i in range (0,100):
    if blockchain[i]['data']==pk:
        cid=int(blockchain[i]['bid'])
        break
    else:
        pass

'''###
Client
###'''
def login():
    username=input("Username:")
    password=input("Password:")
    data=username+password
    data=((crypt.hashthis(data)).encode())
    #print(data)
    s.send(data)
    resp=s.recv(1024)
    print(resp)

def register():
    username=input("Username:")
    password=input("Password:")
    email=input("Email:")
    data=username+password
    data=crypt.hashthis(data)
    email=crypt.hashthis(email)
    data=data+'*'+email
    s.send(data.encode())
    
def details():
    op=input("[1]Register\n[2]Login\n:")
    s.send(op.encode())
    op=int(op)
    if op == 1:
        register()
    elif op== 2 :
        login()
    else:
        print("Error:")

import socket
import requests

ip="127.0.0.1"
port=4411
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.connect((ip,port))
print('[+]Connected to',s)

# Load server public key
sid=int(s.recv(1024))
spub=blockchain[sid]['data'].encode()
SPUB=RSA.importKey(spub)
# Send String
string=b'hello'
sign=private.sign(string,'')
data=str([cid,string,sign]).encode()
s.send(data)
#Step 2 recieve data
sign=s.recv(2048).decode()
sign=eval(sign)
sign=(SPUB.verify(string,sign))
if sign==True:
    print("Connection Done")
    details()
else:
    print("false")
