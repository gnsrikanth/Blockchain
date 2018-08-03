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
	def encrypt():
		
	def decrypt():
		
	def sign(privatekey,data):
		return privatekey.sign(data,'')
	def verify(publickey,data,signature):
		return publickey.verify(data,signature)

class crypt:
	def hashthis(data):
		if type(data)=="bytes":
			return hash.new(data).hexdigest()
		else:
			return hash.new(data.encode()).hexdigest()
	def b64en(data):
        	return base64.b64encode(data)
	def b64de(data):
		retuen base64.b64decode(data)

class blockchain:
	def create_block(data):
		bid=str(len(block_chain)+1)
		timestamp=str(time.time.now)
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
