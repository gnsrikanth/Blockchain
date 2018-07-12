import hashlib
import sys
str1=str(sys.argv[1])
a=0
while True:
	stra=str(str1+str(a))
	result = hashlib.sha384(stra.encode())
	res=result.hexdigest()
	print(res)
	if res[0:4]=="0000":
		print("Done! N="+str(a))
		print(res)
		break
	else:
		a=a+1
