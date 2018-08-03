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
	def encrypt():
	def decrypt():
	def sign(privatekey,data):
		retuen privatekey.sign(data,'')
	def verify(publickey,data,signature):
		return publickey.verify(data,signature)
class crypt:
