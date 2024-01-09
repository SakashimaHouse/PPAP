import hashlib
import socket
import base64
import argparse
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import threading
from random_art.randomart import draw, drunkenwalk
import queue

def parse_arg() -> bool:
    """
    argparseを使った引数の解析を行います。
    返り値：
        secure:bool
    プログラムの流れ：
            ソフトウェアのヘルプ情報を設定
            オプションを設定
            引数をparse()
            parseした引数を変数に代入
    """
    parser = argparse.ArgumentParser(
        prog='PPAP Server',
        description='パスワード付きzipファイルを送信します パスワードを送信します 暗号化 プロトコル',
        epilog='I have a zip.\tI have a password.\tUh Passworded Zip file.\tI have a network connection.\tI have sent that with password.\tUh PPAP!.')
    parser.add_argument('-s', '--secure',
                        action='store_true', help='ハイブリッド暗号通信を使う')
    args = parser.parse_args()
    return (args.secure)


def receive_data_until_end(con) -> bytes:
    """
    接続終了までセグメントを受信する
    """
    progress=queue.Queue()
    end_request=queue.Queue()
    received_length=0
    threading.Thread(target=print_receiving_progress,args=(progress,end_request)).start()
    data = []
    print("受け取り中")
    while True:
        received_length+=1024
        progress.put(received_length)
        temp = con.recv(1024)
        data.append(temp)
        if not temp:
            break
    con.sendall(bytes(b"ACK"))
    print("受け取り終了          ")#\rを使ってプログレス表示をしているのでスペースを入れて残っている表示をクリアする
    end_request.put(received_length)
    return (b''.join(data))
def print_receiving_progress(progress:queue.Queue,end_request:queue.Queue):
    while end_request.empty():
          print("progress:"+str(progress.get()),end='\r')
    print("progress:"+str(end_request.get())+"bytes\n\t完了")

def wait_connection(port: int) -> socket.socket:
    """
    指定されたポートで接続を待つ
    """
    server.bind(("", port))
    server.listen()
    con, addr = server.accept()
    return (con)


def generate_priv_key() -> RSA.RsaKey:
    keyPair = RSA.generate(bits=2048)
    try:
        os.mkdir(".privK")
    except:
        pass
    with open(".privK"+os.path.sep+"private.pem", 'bw') as f:
        f.write(keyPair.export_key())
        f.close()
    return keyPair


def get_or_create_priv_key_if_not_exist() -> RSA.RsaKey:
    if os.path.exists(".privK"+os.path.sep+"private.pem"):
        with open(".privK"+os.path.sep+"private.pem", 'br') as f:
            key = f.read()
            if len(key) < 10:
                keypair = generate_priv_key()
            else:
                keypair = RSA.import_key(key)
            f.close()
            return keypair
    else:
        return generate_priv_key()


def establish_ppaps_connection(con: socket.socket) -> Fernet:
    """
    セキュア通信の準備として鍵交換を行う
    プログラムの流れ
        サーバ側の公開鍵を送る
        クライアントから共通鍵を受け取る
        この共通鍵を復号化し、呼び出し元に返す
    """
    keyPair = get_or_create_priv_key_if_not_exist()
    con.sendall(keyPair.public_key().export_key())
    print("このサーバーの公開鍵:")
    print(draw(drunkenwalk(hashlib.sha256(
        keyPair.public_key().export_key()).digest()), "BLAKE2b/64"))
    con.recv(1024)  # receive ACK
    encrypted_common_key = con.recv(4096)
    con.sendall(bytes(b"ACK"))
    decryptor = PKCS1_OAEP.new(keyPair)
    common_key = decryptor.decrypt(encrypted_common_key)
    cipher_suite = Fernet(common_key)
    return cipher_suite


def decrypt(cipher_encrypted_text, cipher_suite: Fernet) -> bytes:
    """
    base64デコードしたのち、cipher_suiteで複合化する。
    """
    return (cipher_suite.decrypt(cipher_encrypted_text))

def receive_checked_data(con:socket.socket,cipher_suite:Fernet)->str:
    hash=decrypt(con.recv(1024),cipher_suite)
    con.sendall(bytes(b"ACK"))
    data=decrypt(con.recv(1024),cipher_suite)
    con.sendall(bytes(b"ACK"))
    if hashlib.sha256(data).digest()==hash:
        return data.decode("utf-8")
    print("ハッシュが一致しません")
    exit(0)

def save_bfile(path, b_contents):
    """
    バイナリデータをファイルに保存する
    """
    print("追加ファイル: "+path)
    with open(path, 'bw') as f:
        f.write(b_contents)

# TODO: チェックサムの算出と検証
def ppaps(server: socket.socket):
    """
    ファイルやその他情報をハイブリッド暗号化を用いて受け取る
    """
    con = wait_connection(26026)
    cipher_suite = establish_ppaps_connection(con)
    name = receive_checked_data(con,cipher_suite)
    passwd = receive_checked_data(con, cipher_suite)
    file_hash = decrypt(con.recv(1024), cipher_suite)
    con.sendall(bytes(b"ACK"))
    data = decrypt(receive_data_until_end(con), cipher_suite)
    if hashlib.sha256(data).digest()==file_hash:
        save_bfile(name, data)
        print(f"ZIPファイルのパスワード: {passwd}")
    else:
        print("ファイルハッシュが一致しません")
    con.close()
    server.close()


# TODO: チェックサムの算出と検証
def ppap(server: socket.socket):
    """
    ファイルやその他情報を通常の通信方法で受け取る
    """
    con = con = wait_connection(26025)
    name = con.recv(1024).decode("utf-8")
    con.sendall(bytes(b"ACK"))
    passwd = con.recv(1024).decode("utf-8")
    con.sendall(bytes(b"ACK"))

    data = base64.b64decode(receive_data_until_end(con))

    save_bfile(name, data)
    print("ZIPファイルのパスワード: "+passwd)
    con.close()
    server.close()


if __name__ == '__main__':
    """
    このpythonファイルの処理はここから始まります
    流れ：
        引数解析
        解析した引数を変数に代入
        -s,--secureを使用しているなら、
            PPAPSコネクションを使う
        そうでないなら
            PPAPコネクションを使う
    """
    server = socket.socket()
    secure = parse_arg()
    if secure:
        ppaps(server)
    else:
        ppap(server)
# threading.Thread(target=)
