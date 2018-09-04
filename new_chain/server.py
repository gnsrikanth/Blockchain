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

#pk=str((crypt.b64en(public.exportKey('PEM'))).decode())
pk=str(((public.exportKey('PEM'))).decode())
requests.post('http://127.0.0.1:5000', data = {'key':pk})


# GET BLOCKCHAIN
blockchain=requests.get("http://127.0.0.1:5000/get_chain")
blockchain=blockchain.text
blockchain=json.loads(blockchain)


#get blockchain ID
for n in range  (0,len(blockchain)):
    if (pk)==(blockchain[n]['data']):
        bid=int(blockchain[n]['id'])-1
'''        
#SERVER
'''
import socket
import requests

ip="0.0.0.0"
port=4444
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((ip,port))
s.listen(1)
conn,addr=s.accept()
print('[+]Connected to',addr)

recv_str=conn.recv(2048)
recv_str=eval(recv_str.decode())
print(recv_str)

#get blockchain
blockchain=requests.get("http://127.0.0.1:5000/get_chain")
blockchain=blockchain.text
blockchain=json.loads(blockchain)
#Get Public Key
pk=blockchain[int(recv_str[0])]['data']
PK=RSA.importKey(pk.encode())

if (PK.verify(recv_str[1].encode(),recv_str[2])) == True:
    print("Yes!")
    '''
    DO THIS
    '''
else:
    print("Error")
