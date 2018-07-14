import datetime
import hashlib
import json
from flask import Flask, jsonify
class Blockchain:
   def __init__(self):
      self.chain=[]
      self.create.block(proof=0,previous_hash='0',data)
   def create_block(self,proof,previous_hash,data):
      block={'index':len(self.chain) + 1,
            'timestamp':str(datetime.datetime.now()),
            'proof':proof,
            'previous_hash':previous_hash,
            'data':data}
