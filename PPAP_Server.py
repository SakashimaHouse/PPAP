import socket
import base64
# プロトコル自体の再考
server = socket.socket()
server.bind(("", 26025))
server.listen()
client,addr = server.accept()
data=b""
while True:
    temp = client.recv(1024)
    data+=temp
    if not temp:
         break
splited_data=str(data).split("\\n")
with open(str(splited_data[0]), 'bw') as f:
    f.write(base64.b64decode(splited_data[1]))
print("password is "+splited_data[2])
client.close()
server.close()