import os
import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SERVER_HOST = "172.18.0.3"
SERVER_PORT = 6375

KEY_SIZE = 32
NONCE_SIZE = 12
SIGNATURE_SIZE = 64
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
    print("[Client] Starting...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # 連線伺服器
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print("[Client] Connected")

        # 創建X25519金鑰
        client_x25519_private = X25519PrivateKey.generate()
        client_x25519_public = client_x25519_private.public_key()
        client_x25519_public_bytes = client_x25519_public.public_bytes_raw()

        # 將客戶端的X25519公鑰傳送到伺服器
        send_all(client_socket, client_x25519_public_bytes)

        # 接收伺服器的X25519公鑰
        server_x25519_public_bytes = receive_all(client_socket, KEY_SIZE)
        server_x25519_public = X25519PublicKey.from_public_bytes(server_x25519_public_bytes)

        # X25519共享金鑰
        shared_secret = client_x25519_private.exchange(server_x25519_public)

        # 使用HKDF-SHA256派生ChaCha金鑰
        derived_key = HKDF(algorithm = hashes.SHA256(), length = KEY_SIZE, salt = None, info = b"ssh-like-handshake").derive(shared_secret)

        # 建立ChaCha20-Poly1305
        chacha = ChaCha20Poly1305(derived_key)
        print("[Client] Secure channel established.")

        # 接收伺服器Challenge
        challenge_data = receive_encrypted(client_socket, chacha)
        print(f"[Client] Decrypted challenge from server: {challenge_data}")

        # 載入Ed25519私鑰
        print("[Client] Loading ed25519 private key...")
        with open("ed25519_private.pem", "rb") as key_file:
            client_ed25519_private = load_pem_private_key(key_file.read(), password = None)

        # 確認載入的私鑰是Ed25519
        if not isinstance(client_ed25519_private, Ed25519PrivateKey):
            raise TypeError("The private key is not an Ed25519 private key")

        # 使用Ed25519私鑰簽署Challenge
        signature = client_ed25519_private.sign(challenge_data)

        # 確認Ed25519簽章是否為64 bytes
        if len(signature) != SIGNATURE_SIZE:
            raise ValueError("Invalid Ed25519 signature size")

        # 將簽章傳送到伺服器
        send_encrypted(client_socket, chacha, signature)
        print("[Client] Encrypted signature sent to server.")

        # 接收伺服器的認證結果
        authentication_status = receive_encrypted(client_socket, chacha)

        # 判斷認證結果
        if authentication_status == b"AUTHENTICATION SUCCESS":
            print("[Client] Authentication accepted by server!")
            print("[Client] Starting chat loop...")

        else:
            print("[Client] Authentication failed.")
            raise ConnectionError("Server rejected authentication.")

        while True:
            # 輸入訊息
            message = input("[Client] Enter message (or 'exit' to quit): ")

            # 離開
            if message.lower() == "exit":
                print("[Client] Closing connection.")
                break

            # 將訊息傳送到伺服器
            send_encrypted(client_socket,chacha, message.encode("utf-8"))

            try:
                # 接收伺服器回覆
                decrypted_reply = receive_encrypted(client_socket, chacha)
                print(f"[Server Response]: {decrypted_reply.decode('utf-8')}")

            except ConnectionError:
                print("[Client] Connection closed by server.")
                break

    except Exception as e:
        print("[Client] Error:", e)

    finally:
        client_socket.close()
        print("[Client] Closed")

if __name__ == "__main__":
    main()
