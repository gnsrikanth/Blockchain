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
    def nonce(data):    
        no=0
        while True:
            string=crypt.hashthis(data)+str(no)
            newhash=crypt.hashthis(string)
            if newhash[:4]=='0000':
                break
            else:
                no = no + 1
        return newhash,str(no)
    
    def verify_block(block):
         hash1=crypt.hashthis(block['bid']+block['timestamp']+block['data']+block['publickey']+block['previous_block_hash'])+block['nonce']
         hash2=crypt.hashthis(hash1)
         pk=RSA.importKey(block['publickey'].encode())
         if (hash2==block['blockhash'],pk.verify(hash2.encode(),eval(block['sign']))) == (True,True):
             return True
         else:
             return False
    
    def verify_chain():
        
    def __init__(self):
        bid=str(0)
        timestamp=str(time.time())
        data=str(0)
        publickey=(public.exportKey('PEM').decode())
        previous_block_hash=str(0)
        blockhash,nonce=blockchain.nonce(bid+timestamp+data+publickey+previous_block_hash)
        sign=str(private.sign(blockhash.encode(),''))
        
        block={'bid':bid,
               'timestamp':timestamp,
               'data':data,
               'publickey':publickey,
               'previous_block_hash':previous_block_hash,
               'blockhash':blockhash,
               'nonce':nonce,
               'sign':sign}
        block_chain.append(block)
