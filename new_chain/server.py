import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64
import time
import json

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
#        SERVER		#
#########################

'''
Get Blockchain
'''

blockchain=requests.get("http://127.0.0.1/get_chain")
blockchain=blockchain.text
blockchain=json.loads(blockchain)
myid=2
'''
Step 1 Recieve string
'''

import socket
import requests

ip="0.0.0.0"
port=8080
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((ip,port))
s.listen(1)
conn,addr=s.accept()
print('[+]Connected to',addr)

# String format [id,msg,sign]
recv_str=conn.recv(2048)
recv_str=eval(recv_str)


#Verify
bid,msg,sign=recv_str

Bpublic	= RSA.importKey(blockchain[bid]['public'])

if ersa.verify(Bpublic,msg,sign) == False:
	print("Error")
else:
	conn.send(str([myid,msg,ersa.sign(private,msg)]).encode())
