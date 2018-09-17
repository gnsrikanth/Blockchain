import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64
import time

import random

import json
import requests
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

'''
class load_config():
    f=open("blockchain.config","r")
    data=f.read()
    data=json.loads(data)
    global exam_time
    global answers_time
    global difficulty
    exam_time,answers_time,difficulty = data[0], data[1], data[2]        
'''

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class aescrypt:

    def encrypt(raw, password):
        private_key = hashlib.sha256(password.encode("utf-8")).digest()
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(enc, password):
        private_key = hashlib.sha256(password.encode("utf-8")).digest()
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

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
    
chain=requests.get("http://127.0.0.1:5000/chain")
chain=json.loads(chain.text)


qus=random.randint(1,len(chain))
#Question format    [1,question,ans]

data=eval(chain[qus]['data'])
op,question,ans=data[0],data[1],data[2]
key=(chain[qus]['publickey'])

#Verify_block_here()
print(question)
answers=input("Ans:")

#make answers format 2*question*ans*answers*mypublic*sign
resp=str([2,question,ans,answers,public.exportKey('PEM').decode(),private.sign((public.exportKey('PEM').decode()+answers).encode(),'')])
requests.post("http://127.0.0.1:5000",data={'data':resp})

#chain of ans

chain=requests.get("http://127.0.0.1:5000/ans")
chain=json.loads(chain.text)

ns=len(chain)-1
while len(chain)>0:
    if (str(chain[ns]['data']))[1:2]=='3':
        if chain[ns]['publickey']==key:
            passwd=chain[ns]['data']
            nl,password=eval(passwd)
            break
        else:
              ns=ns-1   

ans1=(aescrypt.decrypt(ans,password)).decode()
if ans1 == answers:
    print("Pass")
else:
    print("Fail")
