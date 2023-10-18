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


def parse_arg() -> list[str or bool]:
    """
    argparseを使った引数の解析を行います。
    返り値：
        list[
            input_path:str,
            file_name:str,
            folder_name:str,
            target:str,
            secure:bool
        ]
    プログラムの流れ：
        ソフトウェアのヘルプ情報を設定
        オプションを設定
        引数をparse()
        parseした引数を変数に代入
    """
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
    input_object_path: str = args.input
    zip_name: str = os.path.basename(input_object_path)
    folder_name = os.path.basename(
        input_object_path[0:-1] if input_object_path.endswith(os.path.sep) else input_object_path)
    target_host = args.target
    secure_flag = args.secure
    return [input_object_path, zip_name, folder_name, target_host, str(secure_flag)]


def zipdir(target_directory, out_zip_file_path, password):
    """
    ディレクトリをパスワード付きzipファイルに変換します。
    TODO: zip圧縮後のzipファイル内のディレクトリ構造がカレントディレクトリからの相対パスになってしまっている問題
    """
    try:
        os.mkdir("tmp")
    except:
        pass
    with ZipFile(out_zip_file_path, 'w') as zf:
        zf.setpassword(password.encode())
        for foldername, subfolders, filenames in os.walk(target_directory):
            for filename in filenames:
                print(foldername, filename)
                zf.write(os.path.abspath(foldername)+os.path.sep+filename)


def add_line_to_file(filepath, text):
    with open(filepath, 'a') as f1:
        f1.write(text+os.linesep)
        f1.close()


def check_password_protected_zip(file_path: str) -> bool:
    """
    指定されたパスがパスワード付きzipファイルかどうかチェックします。
    """
    try:
        with zipfile.ZipFile(file_path) as zip_file:
            zip_file.testzip()
            return False
    except RuntimeError:  # passwordつきzipファイルだとランタイムエラーが発生する
        return True
    except Exception:
        # そもそもzipファイルでないばあい。そのばあいはzipfile.BadZipFileが発生するはずなのだが
        # exceptにそれを指定するとなぜかきちんと動かない為、Exceptionで吸収している
        return False


def getPass():
    """
    パスワードの入力を求めます。
    入力したパスワードはコンソール上で非表示です。
    返り値：
        パスワード:str
    """
    passwd = getpass.getpass("password:")
    return passwd


def get_files_in_directory(directory) -> list[str]:
    return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.endswith(".pem")]


def is_trusted_pubk(key)->bool:
    for f in get_files_in_direckeytory(key):
        with open(f,"r"):
            return key==RSA.import_key(f.read())


def establish_PPAPS_connection(target: str) -> tuple[socket.socket, Fernet]:
    """
    PPAPS接続を確立します
    """
    con = socket.socket()
    con.connect((target, PORT_PPAPS))
    server_pubkey = con.recv(3000)  # recv pubk
    imported_server_pubk = RSA.import_key(server_pubkey)
    con.sendall(bytes(b"ACK"))
    if not is_trusted_pubK(imported_server_pubK):
        _continue = True
        while (_continue):
            answer = input(
                "未知の公開鍵です。信頼して./pubKs/trusted.listに追加しますか？(Y/N)").lower()
            if answer == "y":
                break
            elif answer == "n":
                exit(0)
            else:
                continue
    add_line_to_file("pubks"+os.path.sep+"trusted.list", server_pubkey)
    ne = server_pubkey.decode("utf-8").split(",")
    public_key = RSA.construct((int(ne[0]), int(ne[1])))
    common_key = Fernet.generate_key()
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_common_key = encryptor.encrypt(common_key)
    con.sendall(encrypted_common_key)
    con.recv(1024)  # receive ACK
    cipher_suite = Fernet(common_key)
    return (con, cipher_suite)


# TODO: チェックサムの算出と検証+署名
def send_file_with_ppap(zip_name, zip_path: str, con: socket.socket, passwd: str):
    """
    ファイルやその他情報を通常の通信を用いて送信します
    """
    print("sending")
    con.sendall(bytes(zip_name, "utf-8"))
    print("sended name")
    con.recv(1024)  # receive ACK
    print("ack")
    con.sendall(bytes(passwd, "utf-8"))
    print("sended passwd")
    con.recv(1024)  # receive ACK
    print("ack")
    print(zip_path)
    with open(zip_path, 'br') as f1:
        con.sendall(base64.b64encode(f1.read()))
        print("sended file")
    con.close()


# TODO: チェックサムの算出と検証
def send_file_with_PPAPS(zip_path: str, cipher_suite: Fernet, passwd: str, zip_name: str, con: socket.socket):
    """
    ファイルやその他情報をハイブリッド暗号を用いて送信します
    """
    con.sendall(base64.b64encode(
        cipher_suite.encrypt(bytes(zip_name, "utf8"))))
    con.recv(1024)  # receive ACK
    con.sendall(base64.b64encode(cipher_suite.encrypt(bytes(passwd, "utf-8"))))
    con.recv(1024)  # receive ACK
    with open(zip_path, 'br') as f1:
        con.sendall(base64.b64encode(cipher_suite.encrypt(f1.read())))
    con.close()


# TODO: 暗号化では、オプションで信頼できる公開鍵リストを使用して、なりすましのサーバに対応可能にする
# ポート番号はppapをbase64(https://v2.cryptii.com/base64/decimal )でデコードした番号
PORT_PPAP = 26025
PORT_PPAPS = 26026
if __name__ == '__main__':
    """
    このpythonファイルの処理はここから始まります
    流れ：
        引数解析
        解析した引数を変数に代入
        -s,--secureを使用しているなら、
            PPAPSコネクションを確立する。
            PPAPSコネクションでファイルを送信する。
        そうでないなら
            PPAPコネクションでファイルを送る
    """
    arg = parse_arg()
    input_object_path: str = arg[0]
    target_host: str = arg[3]
    secure_flag: bool = arg[4] == "True"

    folder_name: str = arg[2]
    input_object_path_is_file: bool = os.path.isfile(input_object_path)
    zip_path: str = input_object_path if input_object_path_is_file else "." + \
        os.path.sep+"tmp"+os.path.sep+folder_name+".zip"
    zip_name: str = os.path.basename(zip_path)
    passwd: str = getPass()
    if secure_flag:
        con, cipher_suite = establish_PPAPS_connection(target_host)
        if input_object_path_is_file:
            if check_password_protected_zip(zip_path):
                send_file_with_PPAPS(
                    zip_path, cipher_suite, passwd, zip_name, con)
            else:
                print("パスワード付きzipファイルのみ送信可能です。")
        else:
            zipdir(input_object_path, zip_path, passwd)
            if check_password_protected_zip(zip_path):
                send_file_with_PPAPS(
                    zip_path, cipher_suite, passwd, zip_name, con)
                os.remove(zip_path)
            else:
                print("パスワード付きzipファイルの作成に失敗しました")
    else:
        con = socket.socket()
        con.connect((target_host, PORT_PPAP))
        if input_object_path_is_file:
            if check_password_protected_zip(input_object_path):
                send_file_with_ppap(zip_name, zip_path, con, passwd)
            else:
                print("パスワード付きzipファイルのみ送信可能です。")
        else:
            zipdir(input_object_path, zip_path, passwd)
            print(zip_path)
            if check_password_protected_zip(zip_path):
                send_file_with_ppap(zip_name, zip_path, con, passwd)
                os.remove(zip_path)
                os.rmdir("tmp")
            else:
                print("パスワード付きzipファイルの作成に失敗しました")


"""
以下コードスペニット
"""


# windowsの標準コマンドであるcompactを使う方法では、/P:オプションが廃止されていたので諦めた
# def make_zip(directory, zipname, passwd):
#     os_version = platform.platform().lower()
#     if "windows" in os_version:
#         subprocess.call(["compact", "/C", "/S", "/A", "/I",
#                         "/EXE:","/P:"+passwd, zipname, directory])

# make_zip(input_path, "tmp"+os.path.sep+folder_name, passwd)
