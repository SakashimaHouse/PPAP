# PPAP(Password 付き zip ファイルを送ります Password を送ります Angouka Protocol)

このリポジトリでは TCP ポート 26025 で動作する、PPAP/PPAPS プロトコルの定義と実装例を示します。
PPAPS ではハイブリッド暗号方式を用います。

## 実行方法は以下の通りです

1. python3 -m pip install -r requirements.txt
2. サーバー側`python .\PPAP_Server.py`
3. クライアント側`python .\PPAP_Client.py -i .\testdir\ -t 127.0.0.1`

## Example

### Server

```bash
C:\>python PPAP_Server.py -s
This Server's Public key:
╭──╴randomart.py╶──╮
│             *!** │
│          .. !~_* │
│         .. *.!~. │
│..        .  *=*  │
│..       .   *..*.│
│                .*│
│               . *│
│*             . ..│
│             ...  │
╰───╴BLAKE2b/64╶───╯

testdir.zip
password is P@ssw0rd
```

### Client

```bash
C:\>python PPAP*Client.py -i "C:\Users\spyk4\Downloads\testdir.zip" -t 127.0.0.1 -s
password:
Target Server's public key:
╭──╴randomart.py╶──╮
│             *!** │
│          .. !~_* │
│         .. *.!~. │
│..        .  *=*  │
│..       .   *..*.│
│                .*│
│               . *│
│*             . ..│
│             ...  │
╰───╴BLAKE2b/64╶───╯

未知の公開鍵です。信頼して./pubKs/trusted1.pem に追加しますか？(Y/N)Y

```

## PPAP フロー

TCP コネクション確立  
↓  
ファイル名
↓
パスワード
↓
zip ファイル
↓  
完了

## PPAPS フロー

TCP コネクション確立  
↓  
サーバから公開鍵送信  
↓  
クライアントから公開鍵で暗号化した共通鍵を送信  
↓  
以後共通鍵で暗号化した状態で PPAP と同じフローの通信を行う
