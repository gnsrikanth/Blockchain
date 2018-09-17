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
blockchain=requests.get("http://127.0.0.1:5000/get")
blockchain=blockchain.text
blockchain=json.loads(blockchain)

#Find my id SID
for i in range (0,100):
    if blockchain[i]['data']==pk:
        sid=int(blockchain[i]['bid'])
        break
    else:
        pass
'''        
#SERVER
'''

def register():
    data=conn.recv(2048)
    print(data)
    data=data.decode()
    requests.post('http://127.0.0.1:5000', data = {'key':data})    
    
def login():
    bc= (conn.recv(1024)).decode()
    blockchain1=requests.get("http://127.0.0.1:5000/get")
    blockchain1=blockchain1.text
    blockchain1=json.loads(blockchain1)
    for i in range (1,len(blockchain1)):
        if "---" not in blockchain1[i]['data']:
            bbc,lyt=blockchain1[i]['data'].split('*')
            print(bbc)
            if bbc == bc :
                print("OKAY")
                conn.send(b'True')
            else:
                print("FALSE")
                conn.send(b'False')
        else:
            pass
            
def details():
    op=(conn.recv(1024)).decode()
    op=int(op)
    if op == 1:
        register()
    if op == 2:
        login()
import socket
import requests
ip="0.0.0.0"
port=4411
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((ip,port))
s.listen(1)
conn,addr=s.accept()

'''
STEP 1 recieve client id and send string 
'''
conn.send(str(sid).encode()) # Send id
data=conn.recv(2048) #recieve data
data=eval(data)

#update blockchain
blockchain=requests.get("http://127.0.0.1:5000/get")
blockchain=blockchain.text
blockchain=json.loads(blockchain)
#client public key
cpub=blockchain[int(data[0])]['data'].encode()
Cpub=RSA.importKey(cpub)
resp1=Cpub.verify(data[1],data[2])

if resp1 == True:
    sign=private.sign(data[1],'')
    conn.send(str(sign).encode())
    #Done verification
    details()
else:
    print("False")