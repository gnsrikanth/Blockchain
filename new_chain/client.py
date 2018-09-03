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

#########################
#        Client		#
#########################

'''
Get Blockchain
'''

blockchain=requests.get("http://127.0.0.1:5000/get_chain")
blockchain=blockchain.text
blockchain=json.loads(blockchain)
myid=1
'''
Step 1 Recieve string
'''

import socket
import requests

ip="127.0.0.1"
port=1234
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.connect((ip,port))
print('[+]Connected to',s)

# String format [id,msg,sign]
msg="Hello"
message=str([myid,msg,ersa.sign(private,msg)]).encode()
s.send(message)

#time.sleep(0.5)
#verify

message=s.recv(2048)
bid,msg1,sign=eval(message.decode())
print((crypt.b64de(blockchain[bid]['publickey'])).decode())
Bpublic	= RSA.importKey((crypt.b64de(blockchain[bid]['publickey'])).decode())

if Bpublic.verify(msg,sign) == False: ##### !! CHANGE THIS TO False
	print("Error")
else:
	print("WORKING!")
