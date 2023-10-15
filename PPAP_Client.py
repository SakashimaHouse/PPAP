import argparse
import os
import getpass
import zipfile
import socket
import base64
from zipencrypt import ZipFile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
import binascii
# TODO: 公開鍵認証を使ったPPAPSの実装

# 引数の解析
parser = argparse.ArgumentParser(
    prog='PPAP Client',
    description='パスワード付きzipファイルを送信します パスワードを送信します 暗号化 プロトコル',
    epilog='I have a zip.\tI have a password.\tUh Passworded Zip file.\tI have a network connection.\tI have sent that with password.\tUh PPAP!.')
parser.add_argument('-i', '--input', required=True, nargs='?',
                    help='送信したいディレクトリかパスワード付きzipファイル')
parser.add_argument('-t', '--target', required=True,
                    nargs='?', help='ターゲットのIP')
parser.add_argument('-s', '--secure',
                    action='store_true', help='ハイブリッド暗号通信を使う')
args = parser.parse_args()
input_path: str = args.input
file_name: str = os.path.basename(input_path)
folder_name = os.path.basename(
    input_path[0, -1] if input_path.endswith(os.path.sep) else input_path)
target = args.target
secure = args.secure


def zipdir(directory, zipname, password):
    print(zipname)
    with ZipFile(zipname, 'w') as zf:
        zf.setpassword(password.encode())
        for foldername, subfolders, filenames in os.walk(directory):
            for filename in filenames:
                print(foldername, filename)
                zf.write(os.path.abspath(foldername)+os.path.sep+filename)


def check_password_protected_zip(file_path: str) -> bool:
    try:
        with zipfile.ZipFile(file_path) as zip_file:
            zip_file.testzip()
            return False
    except RuntimeError:
        return True


def getPass():
    passwd = getpass.getpass("password:")
    return passwd


if secure:
    port = 26026
    con = socket.socket()
    con.connect((target, port))
    temp = con.recv(1024)
    ne = temp.decode("utf-8").split("\n")
    public_key = RSA.construct((int(ne[0]), int(ne[1])))
    common_key = Fernet.generate_key()
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(common_key)
    con.sendall(binascii.hexlify(encrypted))
    temp = con.recv(1024)  # receive ACK
    cipher_suite = Fernet(common_key)
    if os.path.isfile(input_path):
        if check_password_protected_zip(input_path):
            passwd = getPass()
            with open(input_path, 'br') as f1:
                b64_file = base64.b64encode(f1.read())
                content = cipher_suite.encrypt(
                    bytes(file_name, "utf-8")+b"\n"+b64_file+b"\n"+bytes(passwd, "utf-8"))
                print(content)
                con.sendall(base64.b64encode(content))
    else:
        folder_name = folder_name+".zip"
        passwd = getPass()
        zipdir(input_path, "tmp"+os.path.sep+folder_name, passwd)
        # make_zip(input_path, "tmp"+os.path.sep+folder_name, passwd)
        with open("tmp"+os.path.sep+folder_name, 'br') as f1:
            b64_file = base64.b64encode(f1.read())
            con.sendall(bytes(folder_name, "utf-8")+b"\n"+b64_file+b"\n")
            con.sendall(bytes(passwd+"\n", "utf-8"))
        os.remove("tmp"+os.path.sep+folder_name)
        cipher_text = cipher_suite.encrypt(file_name.encode("utf-8"))
else:
    port = 26025  # ppapをbase64デコードした番号 -> 26025 https://v2.cryptii.com/base64/decimal
    con = socket.socket()
    con.connect((target, port))
    if os.path.isfile(input_path):
        if check_password_protected_zip(input_path):
            passwd = getPass()
            with open(input_path, 'br') as f1:
                b64_file = base64.b64encode(f1.read())
                con.sendall(bytes(file_name, "utf-8")+b"\n"+b64_file+b"\n")
                con.sendall(bytes(passwd+"\n", "utf-8"))
    else:
        folder_name = folder_name+".zip"
        passwd = getPass()
        zipdir(input_path, "tmp"+os.path.sep+folder_name, passwd)
        # make_zip(input_path, "tmp"+os.path.sep+folder_name, passwd)
        with open("tmp"+os.path.sep+folder_name, 'br') as f1:
            b64_file = base64.b64encode(f1.read())
            con.sendall(bytes(folder_name, "utf-8")+b"\n"+b64_file+b"\n")
            con.sendall(bytes(passwd+"\n", "utf-8"))
        os.remove("tmp"+os.path.sep+folder_name)


# windowsの標準コマンドであるcompactを使う方法では、/P:オプションが廃止されていたので諦めた
# def make_zip(directory, zipname, passwd):
#     os_version = platform.platform().lower()
#     if "windows" in os_version:
#         subprocess.call(["compact", "/C", "/S", "/A", "/I",
#                         "/EXE:","/P:"+passwd, zipname, directory])
