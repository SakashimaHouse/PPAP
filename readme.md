# PPAP
![logo](./resources/logo.png)
このプロジェクトははTCPで動作するパスワード付きZIPファイルを送信するためのプロトコルの定義と実装例です。  
ハイブリッド暗号方式を使用する暗号化通信にも対応しています。

## Requirements
Python 3.10+  

## Installation
1. リポジトリのクローン
```
$ git clone https://github.com/SakashimaHouse/PPAP.git
$ cd ./PPAP
```
2. 依存関係のインストール
```
$ pip install -r requirements.txt
```

## Usage
1. サーバーの起動
```
$ python PPAP_Server.py -s

```
2. パスワード付きZIPファイルを作成
```
$ sudo apt-get install zip -y
$ mkdir example
$ zip --encrypt -password P@ssw0rd ./example.zip ./example
```
3. ファイルの送信
```
$ python PPAP_Client.py -i "./example.zip" -t 127.0.0.1 -s
```

## Logic
### PPAP (非暗号化プロトコル)
![logic_ppap](./resources/logic_ppap.png)

### PPAPS (暗号化プロトコル)
![logic_ppaps](./resources/logic_ppaps.png)

## License
このプロジェクトはMIT Licenseに基づきライセンスされています