# SSH Teaching Works 

I. Project Overview

This program establishes a secure, SSH-like client-server communication system. It uses X25519 for key exchange, HKDF-SHA256 for key derivation, and ChaCha20-Poly1305 for encrypted communication. It also uses Ed25519 digital signatures to authenticate the client. After successful authentication, the client and server can communicate securely through an encrypted chat.

II. Development Environment
- Programming Language: Python
- Editor / IDE: Visual Studio Code

III. Dependencies
- Cryptography: It is a cryptographic library that provides many ready-to-use and secure cryptographic algorithms.

IV. Operating Steps

1. Generate an Ed25519 public-private key pair in OpenSSH format.
2. Deploy server.py and client.py on two separate computers, and modify the IP address and port in the code according to the network environment.
3. Configure the Ed25519 public key on the Server and the corresponding private key on the Client.
4. Run the programs on their respective computers.
