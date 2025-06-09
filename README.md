# Messenger
**Secure Linux messenger with end-to-end RSA+AES encryption**

## 🔐 Features

- broadcast to all clients
- sending private secured messages
## 🛠 HowToUse

- a:"message" - broadcast to all people
- "client's username":"message" - to send private message to other client
## 🚀 Installation

```bash
sudo apt update
sudo apt install libssl-dev
```
## 🔑 Build & Run
### 1. Download "Client.cpp" and "Server.cpp"

#### on server machine
1. Choose directory with files in command terminal
```
g++ Server.cpp -o server -lssl -lcrypto
```
2. Write command:
```
./server
```

#### on clients machines
1. In "Client.cpp" set 305 line inet_addr on your server's IP
2. Choose directory with files in command terminal
3. Write command:
```
g++ Client.cpp -o client -lssl -lcrypto
```
4. run after server:
```
./client
```
