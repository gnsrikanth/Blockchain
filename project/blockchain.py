import time
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256 as hash
import base64

class Blockchain:
  def __init__():
      chain=[]
  
  def b64(data):
    b64=base64.b64encode(data)
    return b64
  
  def create_block(data):
    new_block={'id':str(len(chain)+1),
              'address':b64(public_key),
              'time':str(time.time()),
              ''}
