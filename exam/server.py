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
 
class aescrypt:
    BLOCK_SIZE = 16
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]

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
    
block_chain=[]

class blockchain:
    
    #Difficulty
    def nonce(data):    
        no=0
        while True:
            string=crypt.hashthis(data)+str(no)
            newhash=crypt.hashthis(string)
            if newhash[:3]=='000':
                break
            else:
                no+=1
        return newhash,str(no)
    
    def verify_block(block):
         hash1=crypt.hashthis(block['bid']+block['timestamp']+block['data']+block['publickey']+block['previous_block_hash'])+block['nonce']
         hash2=crypt.hashthis(hash1)
         pk=RSA.importKey(block['publickey'].encode())
         if (hash2==block['blockhash'],
             pk.verify(hash2.encode(),eval(block['sign'])),
             block_chain[ int(block['bid']) -1 ]['blockhash'] == block['previous_block_hash']   ) == (True,True,True):
             
             return True
         else:
             return False
    
    def verify_chain(bc):
        i=1
        while i<len(bc):
           if blockchain.verify_block(bc[i]) == True:
               i+=1
               resp = True
           else:
               resp = False
               break
        return resp
    
    def create_block(data):
        bid=str(int(block_chain[-1]['bid'])+1)
        timestamp=str(time.time())
        data=str(data)
        publickey=(public.exportKey('PEM').decode())
        previous_block_hash=block_chain[-1]['blockhash']
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
    
    def queue(data):
        # Format in [time, data, public, signature]
        data =  sorted(data)
        for d in data:
            text= d[1]
            sign= d[3]
            publickey=RSA.importKey(d[2].encode())
            if publickey.verify(text.encode(),sign) == True:
                pass
            else:
                data.remove(d)
        return data
    
    def check_long_chain(new_chain):
        if len(block_chain) < len(new_chain):
            if blockchain.verify_chain(new_chain)== True:
                block_chain=new_chain
        else:
            pass

    def consensus():
        f=open("nodes","r")
        nodes=json.loads(f.read())
        for n in nodes:
            try:
                r=requests.get(f"http://{n}/get")
                chain=json.loads(r.text)
                check_long_chain(chain)
            except:
                print("[-]Error with consensus")

######################
#   SERVER 
######################
blockchain()

queue=[]
app = Flask(__name__)
@app.route('/', methods = ['POST'])
def index():
    text = request.form['answers']
    if len(queue) < 3:
        queue.append(eval(text))
    else:
        blockchain.create_block(blockchain.queue(queue))
        queue.clear()
    return "Done",200
'''
####
    text=eval(text)
    data=str(text[1])
    pb=text[2]
    pb=RSA.importKey(pb.encode())
    sign=text[3]
    if pb.verify(data.encode(),sign) == True:
        blockchain.create_block(str(text))
    else:
        print("Failed verifing block")
####
''' 


@app.route('/questions',methods=['GET'])
def questions():
    f=open("questions.txt","r")
    return (f.read()), 200

@app.route('/answers',methods=['GET'])
def answers():
    f=open("answers.txt","r")
    return (f.read()), 200

@app.route('/chain',methods=['GET'])
def chain():
    return jsonify(block_chain), 200

app.run(host = '0.0.0.0', port = 5000)
