import argparse
import os
import getpass
import zipfile
import socket
import base64
from zipencrypt import ZipFile
import platform
import subprocess
import sys
# TODO: 公開鍵認証を使ったPPAPSの実装


def zipdir(directory, zipname, password):
    print(zipname)
    with ZipFile(zipname, 'w') as zf:
        zf.setpassword(password.encode())
        for foldername, subfolders, filenames in os.walk(directory):
            for filename in filenames:
                print(foldername, filename)
                zf.write(os.path.abspath(foldername)+os.path.sep+filename)
# def make_zip(directory, zipname, passwd):
#     os_version = platform.platform().lower()
#     if "windows" in os_version:
#         subprocess.call(["compact", "/C", "/S", "/A", "/I",
#                         "/EXE:","/P:"+passwd, zipname, directory])


def check_password_protected_zip(file_path: str) -> bool:
    try:
        with zipfile.ZipFile(file_path) as zip_file:
            zip_file.testzip()
            return False
    except RuntimeError:
        return True


parser = argparse.ArgumentParser(
    prog='PPAP server',
    description='Receive a Passworded zip file and a password.',
    epilog='I have a zip.\t\
                        I have a password.\t\
                        Uh Passworded Zip file.\t\
                            I have a network connection.\t\
                                I have sent that with password.\t\
                                    Uh PPAP!.')
parser.add_argument('-i', '--input', required=True, nargs='?',
                    help='folder or passworded zip file path')
parser.add_argument('-t', '--target', required=True,
                    nargs='?', help='target Node IP address')
args = parser.parse_args()
input_path: str = args.input
file_name: str = os.path.basename(input_path)
folder_name = os.path.basename(
    input_path[0, -1] if input_path.endswith(os.path.sep) else input_path)
target = args.target
port = 26025  # base64(ppap) -> 26025 https://v2.cryptii.com/base64/decimal


def getPass():
    passwd = getpass.getpass("password:")
    return passwd


if os.path.isfile(input_path):
    if check_password_protected_zip(input_path):
        passwd = getPass()
        with open(input_path, 'br') as f1:
            b64_file = base64.b64encode(f1.read())
            con = socket.socket()
            con.connect((target, port))
            con.sendall(bytes(file_name, "utf-8")+b"\n"+b64_file+b"\n")
            con.sendall(bytes(passwd+"\n", "utf-8"))
else:
    folder_name = folder_name+".zip"
    passwd = getPass()
    zipdir(input_path, "tmp"+os.path.sep+folder_name, passwd)
    # make_zip(input_path, "tmp"+os.path.sep+folder_name, passwd)
    with open("tmp"+os.path.sep+folder_name, 'br') as f1:
        b64_file = base64.b64encode(f1.read())
        con = socket.socket()
        con.connect((target, port))
        con.sendall(bytes(folder_name, "utf-8")+b"\n"+b64_file+b"\n")
        con.sendall(bytes(passwd+"\n", "utf-8"))
    os.remove("tmp"+os.path.sep+folder_name)
