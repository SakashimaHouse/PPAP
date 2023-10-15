import socket
import base64
import os
import threading
import argparse
from cryptography.fernet import Fernet
# TODO: check if i have to add %appdata%\Python\Python311\Scripts to path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
server = socket.socket()

parser = argparse.ArgumentParser(
    prog='PPAP Server',
    description='パスワード付きzipファイルを送信します パスワードを送信します 暗号化 プロトコル',
    epilog='I have a zip.\tI have a password.\tUh Passworded Zip file.\tI have a network connection.\tI have sent that with password.\tUh PPAP!.')
parser.add_argument('-s', '--secure',
                    action='store_true', help='ハイブリッド暗号通信を使う')
args = parser.parse_args()
secure = args.secure


def ppaps():
    keyPair = RSA.generate(bits=1024)
    server.bind(("", 26026))
    server.listen()
    client, addr = server.accept()
    client.sendall(bytes(str(keyPair.publickey().n) +
                   "\n"+str(keyPair.publickey().e)+"\n", "utf-8"))
    encrypted_key = binascii.unhexlify(client.recv(1024))
    decryptor = PKCS1_OAEP.new(keyPair)
    common_key = decryptor.decrypt(encrypted_key)
    cipher_suite = Fernet(common_key)
    client.sendall(bytes("ACK"+"\n", "utf-8"))
    data = b""
    while True:
        temp = client.recv(1024)
        data += temp
        if not temp:
            break
    print(data)
    splited_data = cipher_suite.decrypt(
        base64.b64decode(data)).decode('utf-8').split("\n")
    with open(splited_data[0], 'bw') as f:
        f.write(base64.b64decode(splited_data[1]))
    print("password is "+splited_data[2])
    client.close()
    server.close()


def ppap():
    server.bind(("", 26025))
    server.listen()
    client, addr = server.accept()
    data = b""
    while True:
        temp = client.recv(1024)
        data += temp
        if not temp:
            break
    splited_data = data.decode('utf-8').split("\n")
    with open(splited_data[0], 'bw') as f:
        f.write(base64.b64decode(splited_data[1]))
    print("password is "+splited_data[2])
    client.close()
    server.close()


if secure:
    ppaps()
else:
    ppap()
# threading.Thread(target=)
