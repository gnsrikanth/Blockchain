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
	def encrypt(rsa_publickey,plain_text):
		cipher_text=rsa_publickey.encrypt(plain_text,32)[0]
		b64cipher=base64.b64encode(cipher_text)
		return b64cipher
	def decrypt(b64cipher, rsa_privatekey):
		decoded_ciphertext = base64.b64decode(b64cipher)
		plaintext = rsa_privatekey.decrypt(decoded_ciphertext)
		return plaintext
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
#        CLIENT     		#
#########################
c=rsacrypt()
private,public=c.gen()
import socket
import requests

ip="127.0.0.1"
port=8080
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.connect(ip,port)
print('[+]Connected! ',s)

#### get chain
def getchain(ip,port):
	chain=requests.get(f'http://{ip}:{port}/get_chain')
	return (chain.text)

rand_string=

my_block="2" # NUMBER OF THE BLOCK
def step1(recv_block,my_block_id):
	public_recv=RSA.importKey(recv_block['publickey']) 	# reciever public key
	enmsg=rsacrypt.encrypt(rand_string,public_recv)
	sign=rsacrypt.sign(private,enmsg) #sign the message with our private key, encrypt message with public of reciever
	#publickeystr=(privatekey.exportKey('PEM')).decode()
	hash_string=crypt.hash(rand_string+str(block)+sign)
	data = enmsg+"*"+str(sign)+"*"hash_string
	
	s.send(data.encode())
	
	resp=(s.recv()).decode()
	enmsg,sign,recv_block=resp.split('*')
	public_recv=RSA.importKey(recv_block['publickey'])
	
