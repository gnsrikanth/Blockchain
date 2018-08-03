import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64
import time

block_chain=[]

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

class blockchain:
	def create_block(data):
		bid=str(len(block_chain)+1)
		timestamp=str(time.time())
		data=str(data)
		publickey=str((crypt.b64en(my_publickey.exportKey('PEM'))).decode())
		previous_block_hash=str(crypt.hashthis(str(block_chain[-1])))
		blockhash=str(crypt.hashthis(bid+timestamp+data+publickey+previous_block_hash))
		sign=crypt.b64en(rsacrypt.sign(my_privatekey,hashblock))
		newblock={'id':bid,
			 'timestamp':timestamp,
			 'data':data,
			 'publickey':publickey,
			 'previous_block_hash':previous_block_hash,
			 'blockhash':blockhash,
			 'sign':sign}
		return newbock
	def verify_block(publickey,block,sign):
		publickey=RSA.importKey(crypt.b64de(block['publickey'].encode()))
		blockhash=str(crypt.hashthis(block['bid']+block['timestamp']+block['data']+block['publickey']+block['previous_block_hash']))
		blocksign=crypt.b64de(block['sign'])
		return rsacrpyt.verify(publickey,blockhash,blocksign)
	def __init__(self):
		bid=str(0)
		timestamp=str(time.time())
		data=str(0)
		publickey=str((crypt.b64en(my_publickey.exportKey('PEM'))).decode())
		previous_block_hash=str(0)
		blockhash=str(crypt.hashthis(bid+timestamp+data+publickey+previous_block_hash))
		sign=crypt.b64en(str(rsacrypt.sign(my_privatekey,blockhash)))
		newblock={'id':bid,
			 'timestamp':timestamp,
			 'data':data,
			 'publickey':publickey,
			 'previous_block_hash':previous_block_hash,
			 'blockhash':blockhash,
			 'sign':sign}
		block_chain.append(newbock)

my_privatekey,my_publickey=rsacrypt.gen()
