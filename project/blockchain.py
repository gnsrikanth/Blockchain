import time
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64

class crypt:
  def b64(data):
	return base64.b64encode(data)
  def hashdata(data):
	return hash.new(data).digest()
  def sign(privatekey,data):
	datahash=hash.new(data.encode()).digest()
	return privatekey.sign(datahash,'')

class Blockchain:
  def __init__():
	chain=[]  
      
  def create_block(data):
		new_block={'id':str(len(chain)+1),
                'address':str(crypt.b64(public_key)),
                'time':str(time.time()),
                'data':str(data),
                'myblockhash':str(crypt.hash(((str(len(chain)+1)+(str(crypt.b64(public_key))+(str(time.time())+(str(data))))).encode())),
                'sign':crypt.sign(privatekey,str(crypt.hash(((str(len(chain)+1)+(str(crypt.b64(public_key))+(str(time.time())+(str(data))))).encode())))}
		return new_block
