import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64
import time

class rsacrypt:
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
#########################
#        SERVER		#
#########################
c=rsacrypt()
Aprivate,Apublic=c.gen()
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

def getchain(ip,port):
	chain=requests.get(f'http://{ip}:{port}/get_chain')
	return (chain.text)

def rand_str(string1,blockno):
	

my_block="2" # NUMBER OF THE BLOCK
def step1(recv_block,my_block_id):
	msg=conn.recv(2048)
	enmsg,sign,recv_block=resp.split('*')
	
	public_recv=RSA.importKey(blockchain[recv_block]['publickey']) 	# reciever public key
	enmsg=rsacrypt.decrypt(private,enmsg)
	sign=rsacrypt.sign(private,enmsg) 
	#publickeystr=(privatekey.exportKey('PEM')).decode()
	hash_string=crypt.hash(rand_string+str(block)+sign)
	data = enmsg+"*"+str(sign)+"*"+hash_string
		


