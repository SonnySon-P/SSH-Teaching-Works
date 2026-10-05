import os
import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SERVER_HOST = "172.18.0.3"
SERVER_PORT = 6375

KEY_SIZE = 32
NONCE_SIZE = 12
MAX_DATA = 4096

def send_all(sock, data):
    sock.sendall(data)

def receive_all(sock, length):
    data = b""

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data = data + chunk

    return data

def send_encrypted(sock, chacha, data):
    # 每次傳送新訊息，都要準備一個新的Nonce
    nonce = os.urandom(NONCE_SIZE)

    # 使用ChaCha20-Poly1305加密
    encrypted = chacha.encrypt(nonce, data, None)

    # 確保長度可以放入2 bytes
    if len(encrypted) > 0xFFFF:
        raise ValueError("Encrypted data is too large")

    # 傳送Nonce
    send_all(sock, nonce)

    # 傳送Encrypted Data長度
    send_all(sock, len(encrypted).to_bytes(2, "big"))

    # 傳送Encrypted Data
    send_all(sock, encrypted)

def receive_encrypted(sock, chacha):
    # 接收Nonce
    nonce = receive_all(sock, NONCE_SIZE)

    # 接收加密資料長度
    length_bytes = receive_all(sock, 2)
    length = int.from_bytes(length_bytes, "big")

    # ChaCha20-Poly1305的Authentication Tag是16 bytes
    if length < 16:
        raise ValueError("Invalid encrypted data length")

    if length > MAX_DATA + 16:
        raise ValueError("Data too large")

    # 接收加密資料
    encrypted = receive_all(sock, length)

    # 解密並驗證Authentication Tag
    return chacha.decrypt(nonce, encrypted, None)

def main():
    print("[Server] Starting...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f"[Server] Listening on {SERVER_HOST}:{SERVER_PORT}")

    client_socket, client_address = server_socket.accept()
    print(f"[Server] Client connected: {client_address}")

    try:
        # 接收客戶端的X25519公鑰
        client_x25519_public_bytes = receive_all(client_socket, KEY_SIZE)
        client_x25519_public = X25519PublicKey.from_public_bytes(client_x25519_public_bytes)

        # 創建X25519金鑰
        server_x25519_private = X25519PrivateKey.generate()
        server_x25519_public = server_x25519_private.public_key()
        server_x25519_public_bytes = server_x25519_public.public_bytes_raw()

        # 將伺服器的X25519公鑰傳送到客戶端
        send_all(client_socket, server_x25519_public_bytes)

        # X25519共享金鑰
        shared_secret = server_x25519_private.exchange(client_x25519_public)

        # 使用HKDF-SHA256派生ChaCha金鑰
        derived_key = HKDF(algorithm = hashes.SHA256(), length = KEY_SIZE, salt = None, info = b"ssh-like-handshake").derive(shared_secret)

        # 建立ChaCha20-Poly1305
        chacha = ChaCha20Poly1305(derived_key)
        print("[Server] Secure channel established.")

        # 將Challenge傳送到客戶端 互動式問答式驗證
        challenge = b"CHALLENGE FROM SERVER"
        send_encrypted(client_socket, chacha, challenge)
        print("[Server] Challenge sent.")

        # 接收客戶端Ed25519簽章
        signature = receive_encrypted(client_socket, chacha)
        print("[Server] Signature received.")

        # 載入客戶端Ed25519公鑰
        print("[Server] Loading Ed25519 public key...")
        with open("ed25519_public.pem", "rb") as key_file:
            public_key_bytes = key_file.read()

        # 還原成Ed25519公鑰物件
        client_ed25519_public = load_pem_public_key(public_key_bytes)

        # 確認載入的公鑰是Ed25519
        if not isinstance(client_ed25519_public, Ed25519PublicKey):
            raise TypeError("The public key is not an Ed25519 public key")

        # 驗證Ed25519簽章
        try:
            client_ed25519_public.verify(signature, challenge)
            print("[Server] Authentication SUCCESS.")

        except Exception:
            print("[Server] Authentication FAILED.")
            send_encrypted(client_socket,chacha, b"AUTHENTICATION FAILED")
            return

        # 回覆AUTHENTICATION SUCCESS
        send_encrypted(client_socket, chacha, b"AUTHENTICATION SUCCESS")
        print("[Server] Authentication accepted.")
        print("[Server] Starting chat loop...")

        # 進入互動迴圈
        while True:
            try:
                # 接收Client訊息
                message = receive_encrypted(client_socket, chacha)
                print(f"[Client] {message.decode('utf-8')}")

                # 回覆Client訊息
                response = (f"Received: {message.decode('utf-8')}").encode("utf-8")
                send_encrypted(client_socket, chacha, response)
                print(f"[Server] {response.decode('utf-8')}")

            except ConnectionError:
                print("[Server] Client disconnected.")
                break

    except Exception as e:
        print("[Server] Error:", e)

    finally:
        client_socket.close()
        server_socket.close()
        print("[Server] Closed.")

if __name__ == "__main__":
    main()
