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




def if_there(key):
    f=open('contacts.txt',"r")
    contacts=f.read()
    contacts=eval(contacts)
    key=crypt.hashthis(key.encode())
    if key in contacts:
        return True
    else:
        return False
    
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

#private,public=rsacrypt.gen()
private,public=rsacrypt.getkeys('private.key','public.key')    

class blockchain:
    block_chain=[]
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
         
         #block_chain[ int(block['bid']) -1 ]['blockhash'] == block['previous_block_hash'] 
         pk=RSA.importKey(block['publickey'].encode())
         if (hash2==block['blockhash'],
             pk.verify(hash2.encode(),eval(block['sign']))  ) == (True,True):
             if if_there(block['publickey'])==True:
                 return True
             else:
                 return False
         else:
             return False
    
    def verify_chain(bc):
        i=1
        resp=False
        while i<len(bc):
           if blockchain.verify_block(bc[i]) == True:
               i+=1
               resp = True
           else:
               resp = False
               break
        return resp
    
    def create_block(data):
        bid=str(int(blockchain.block_chain[-1]['bid'])+1)
        timestamp=str(time.time())
        data=str(data)
        publickey=(public.exportKey('PEM').decode())
        previous_block_hash=blockchain.block_chain[-1]['blockhash']
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
        blockchain.block_chain.append(block)
     
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
        blockchain.block_chain.append(block)
   
    def check_long_chain(new_chain):
        if len(blockchain.block_chain) < len(new_chain):
            if blockchain.verify_chain(new_chain)== True:
                blockchain.block_chain=new_chain
        else:
            pass

    def consensus():
        try:
            f=open("nodes.txt","r")
            nodes=(str(f.read())).split('/')
            for n in nodes:
                r=requests.get(f"http://{n}/chain")
                chain=json.loads(r.text)
                blockchain.check_long_chain(chain)
        except:
                print("[-]Error with consensus")
blockchain()
#Questionpaper
f=open("questionpaper.txt","r")
question=f.read()
f.close()
f=open("answers.txt","r")
ans=f.read()
f.close()
passwd="The_password"
ans=aescrypt.encrypt(ans,passwd)

questions1=[1,question,ans.decode()]
# Step3
password=str([3,passwd])

blockchain.consensus()
blockchain.create_block(questions1)

class localFlask(Flask):
    def process_response(self, response):
        SERVER_NAME='hello123'
        #Every response will be processed here first
        response.headers['server'] = SERVER_NAME
        super(localFlask, self).process_response(response)
        return(response)

# Server
app = Flask(__name__)
@app.route('/', methods = ['POST'])
def index():
    text = request.form['data'] 
    blockchain.consensus()
    (blockchain.create_block(text))
    return '',200
    
@app.route('/chain', methods = ['GET'])
def chain():
    return jsonify(blockchain.block_chain), 200

@app.route('/ans', methods = ['GET'])
def ans():
    blockchain.consensus()
    blockchain.create_block(password)
    return jsonify(blockchain.block_chain), 200

app.run(host = '0.0.0.0', port = 5000)