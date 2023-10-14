# PPAP(Password 付き zip ファイルを送ります Password を送ります Angouka Protocol)
  
このリポジトリでは PPAP プロトコルの実装例を示します。
  
## 実行方法は以下の通りです

1. python3 -m pip install -r requirements.txt
2. サーバー側`python .\PPAP_Server.py`
3. クライアント側`python .\PPAP_Client.py -i .\testdir\ -t 127.0.0.1`

## PPAP フロー

TCP コネクション確立  
↓  
ファイル名を送ります  
↓  
base64 化したパスワード付き zip ファイルを送ります  
↓  
パスワードを送ります  
↓
完了
