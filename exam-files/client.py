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



#qus=Random.randint(1,len(chain))

qus=1
#Question format    [1,question,ans]

data=eval(chain[qus]['data'])
op,question,ans=data[0],data[1],data[2]
key=(chain[qus]['publickey'])

myid=crypt.hashthis(key)

questions = eval(question)
q1=questions[0] 
q2=questions[1]
q3=questions[2]
q4=questions[3] 


html=f'''<!DOCTYPE html>
<html>
<title>EXAM[+]</title>
<meta charset="UTF-8"><!--
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
-->
<body class="w3-content" style="max-width:1200px">

<div class="w3-panel">
  <i class="w3-xlarge fa fa-bars"></i>
</div>
<!-- First Grid: Logo & About -->
<div class="w3-row">
<div class="w3-half w3-container">
  <h1 class="w3-xxlarge w3-text-light-grey">ID: {myid}</h1>


<form action="/" method=post>  
<h1 class="w3-xxlarge w3-text-grey">{q1}</h1><br>
<input type="radio" name="options" id="option1" value="a"> A </input><br>
<input type="radio" name="options" id="option2" value="b"> B</input><br>
<input type="radio" name="options" id="option3" value="c"> C </input><br>
<input type="radio" name="options" id="option3" value="d"> D </input><br>
  <h1 class="w3-xxlarge w3-text-grey">{q2}</h1><br>
<input type="radio" name="options1" id="option1" value="a"> A </input><br>
<input type="radio" name="options1" id="option2" value="b"> B</input><br>
<input type="radio" name="options1" id="option3" value="c"> C </input><br>
<input type="radio" name="options1" id="option3" value="d"> D </input><br>
  <h1 class="w3-xxlarge w3-text-grey">{q3}</h1><br>
<input type="radio" name="options2" id="option1" value="a"> A </input><br>
<input type="radio" name="options2" id="option2" value="b"> B</input><br>
<input type="radio" name="options2" id="option3" value="c"> C </input><br>
<input type="radio" name="options2" id="option3" value="d"> D </input><br>
  <h1 class="w3-xxlarge w3-text-grey">{q4}</h1><br>
<input type="radio" name="options3" id="option1" value="a"> A </input><br>
<input type="radio" name="options3" id="option2" value="b"> B</input><br>
<input type="radio" name="options3" id="option3" value="c"> C </input><br>
<input type="radio" name="options3" id="option3" value="d"> D </input><br>
<br>
<button type="submit" class="btn btn-primary btn-md">Submit</button>
</form>

</div>


</body>
</html>
'''


def intersection(lst1, lst2): 
    lst3 = [value for value in lst1 if value in lst2] 
    return lst3 

def ansfunc():
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
    return eval(ans1)

def results(l1,l2):
    return len(intersection(l1,l2))

def results1(questions,ans):
    print(questions)
    print(type(questions))
    print(ans)
    print(type(ans))
    
    questions=eval(questions)
    ans=eval(ans)
    print(type(questions))
    print(type(ans))
    a=0
    for i in range(0,4):
        if questions[i] == ans[i]:
            a=a+1
        else:
            pass
    return str(a)

def makeans(all_answers):
    resp=str([2,question,ans,str(all_answers),public.exportKey('PEM').decode(),private.sign((public.exportKey('PEM').decode()+str(all_answers)).encode(),'')])
    requests.post("http://127.0.0.1:5000",data={'data':resp})
'''
FLASK APP

my_answers=['a','a','c','a']
makeans(my_answers)
main_answers=ansfunc()
results(main_answers,my_answers)
'''

import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse

app = Flask(__name__)
@app.route('/', methods = ['POST'])
def index():
    print("HERE")
    text1 = request.form['options']
    text2 = request.form['options1']
    text3 = request.form['options2']
    text4 = request.form['options3']
    my_answers=[text1,text2,text3,text4]     
    makeans(my_answers)
    main_answers=ansfunc()
    #result=results(main_answers,my_answers)
    result=results1(str(main_answers),str(my_answers))
    print(result)
    my_result=f'''<!DOCTYPE html>
    <html>
    <title>W3.CSS Template</title>
    <meta charset="UTF-8"><!--
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <body class="w3-content" style="max-width:1200px">
    -->
    <div class="w3-panel">
      <i class="w3-xlarge fa fa-bars"></i>
    </div>
    <!-- First Grid: Logo & About -->
    <div class="w3-row">
    <div class="w3-half w3-container">
      <h1 class="w3-xxlarge w3-text-light-grey">ID: {myid}</h1>
<h1 class="w3-xxlarge w3-text-light-grey">Your answers {my_answers}</h1>
<h1 class="w3-xxlarge w3-text-light-grey">Key: {main_answers}</h1>     
      <h1 class="w3-xxlarge w3-text-grey">Your marks are: {result}</h1>
    </div>
    
    
    </body>
    </html>
    '''
    return my_result,200
    
@app.route('/', methods = ['GET'])
def chain():
    return html, 200

app.run(host = '0.0.0.0', port = 5001)