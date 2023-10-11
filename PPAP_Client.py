import argparse
import os
import getpass
import zipfile

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
parser.add_argument('-i','--input',required=True ,nargs='?',help='folder or passworded zip file path')
parser.add_argument('-t','--target',required=True ,nargs='?',help='target Node IP address')
args =parser.parse_args()
input_path=args.input
def getPass():
    passwd=getpass.getpass("password:")
    return passwd
if os.path.isfile(input_path):
    if check_password_protected_zip(input_path):
        passwd=getPass()
        # TODO: エンコード
        # TODO: 送信
else:
    # TODO: パスワード付きZIPに圧縮
    passwd=getPass()
    # TODO: エンコード
    # TODO: 送信