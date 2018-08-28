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
#####
# Step 1 RAND STR
#####
rand_str=conn.recv(1024)
#user,string,str_hash,str_sign=rand_str.split("*")

user,string,str_hash,str_sign=eval(rand_str)[0],eval(rand_str)[1],eval(rand_str)[2],,eval(rand_str)[3]
# get Blockchain
blockchain=requests.get("http://127.0.0.1/get_chain")
blockchain=blockchain.text()
#Find Public key in blockchain
Bpublic=blockchain[user]['publickey']
Bpublic=RSA.importKey(crypt.b64de(block['publickey'].encode()))
str_sign=(int(crypt.b64de(block['sign'])),)
if Bpublic.veryfy(string,str_hash,str_sign) == True:
	print("[+]Done!")
else:
	print("[-]Error")
