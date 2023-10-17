import socket
import base64
import argparse
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


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
    data = b""
    while True:
        temp = con.recv(1024)
        data += temp
        if not temp:
            break
    return (data)


def wait_connection(port: int) -> socket.socket:
    """
    指定されたポートで接続を待つ
    """
    server.bind(("", port))
    server.listen()
    con, addr = server.accept()
    return (con)


def establish_ppaps_connection(con: socket.socket) -> Fernet:
    """
    セキュア通信の準備として鍵交換を行う
    プログラムの流れ
        サーバ側の公開鍵を送る
        クライアントから共通鍵を受け取る
        この共通鍵を復号化し、呼び出し元に返す
    """
    keyPair = RSA.generate(bits=1024)

    con.sendall(bytes(str(keyPair.publickey().n) +
                      "\n"+str(keyPair.publickey().e), "utf-8"))
    con.recv(1024)  # receive ACK
    encrypted_common_key = con.recv(1024)
    con.sendall(bytes(b"ACK"))
    decryptor = PKCS1_OAEP.new(keyPair)
    common_key = decryptor.decrypt(encrypted_common_key)
    cipher_suite = Fernet(common_key)
    return cipher_suite


def decrypt(cipher_encrypted_text, cipher_suite: Fernet) -> bytes:
    """
    base64デコードしたのち、cipher_suiteで複合化する。
    """
    return(cipher_suite.decrypt(
        base64.b64decode(cipher_encrypted_text)))


def save_bfile(path, b_contents):
    """
    バイナリデータをファイルに保存する
    """
    print(path)
    with open(path, 'bw') as f:
        f.write(b_contents)


# TODO: チェックサムの算出と検証
def ppaps(server: socket.socket):
    """
    ファイルやその他情報をハイブリッド暗号化を用いて受け取る
    """
    con = wait_connection(26026)
    cipher_suite = establish_ppaps_connection(con)
    name = decrypt(con.recv(1024), cipher_suite).decode("utf-8")
    con.sendall(bytes(b"ACK"))
    passwd = decrypt(con.recv(1024), cipher_suite).decode("utf-8")
    con.sendall(bytes(b"ACK"))
    data = decrypt(receive_data_until_end(con),cipher_suite)
    save_bfile(name, data)
    print("password is "+passwd)
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
    print("password is "+passwd)
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
