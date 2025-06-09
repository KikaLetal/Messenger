#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <csignal>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <map>
#include <mutex>
#include <vector>

using namespace std;

int client_socket;
mutex cout_mutex;
int pipefd[2];

string Trim(const string& s) {
    size_t start = 0;
    while (start < s.size() && isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }

    if (start == s.size()) {
        return "";  // строка состоит только из пробелов
    }

    size_t end = s.size() - 1;
    while (end > start && isspace(static_cast<unsigned char>(s[end]))) {
        --end;
    }

    return s.substr(start, end - start + 1);
}
//--------генерация RSA ключей------------

EVP_PKEY* Generate_RSA_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if (!ctx) return nullptr;
	
	if(EVP_PKEY_keygen_init(ctx) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return nullptr;
	}

	if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return nullptr;
	}

	EVP_PKEY* pkey = nullptr;
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return nullptr;
	}

	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

string Get_Public_Key_Pem(EVP_PKEY* pkey){
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, pkey);
	char* data;
	long len = BIO_get_mem_data(bio, &data);
	string pem(data, len);
	BIO_free(bio);
	return pem;
}

string Get_Private_Key_Pem(EVP_PKEY* pkey){
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
	char* data;
	long len = BIO_get_mem_data(bio, &data);
	string pem(data, len);
	BIO_free(bio);
	return pem;
}

//-------AES-------

vector<unsigned char> Generate_AES_Key(){
	vector<unsigned char> key(32);
	RAND_bytes(key.data(), key.size());
	return key;
}

vector<unsigned char> AES_Encrypt(const vector<unsigned char>& key, const string& plaintext){
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	vector<unsigned char> iv(16);
	RAND_bytes(iv.data(), iv.size());

	vector <unsigned char> ciphertext(plaintext.size() + 16);
	int len = 0, final_len = 0;

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
	EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());
	EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len);

	ciphertext.resize(len + final_len);
	ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext;
}

string AES_Decrypt(const vector<unsigned char>& key, const vector<unsigned char>& input) {
  if (input.size() < 16) throw runtime_error("invalid AES input: too short");

  vector<unsigned char> iv(input.begin(), input.begin() + 16);
  vector<unsigned char> ciphertext(input.begin() + 16, input.end());

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw runtime_error("failed to create cipher context");

  vector<unsigned char> decrypted(ciphertext.size() + 16); // alloc bigger buffer
  int len = 0, final_len = 0;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_DecryptInit_ex failed");
  }

  if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_DecryptUpdate failed");
  }

  if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_DecryptFinal_ex failed (bad padding?)");
  }

  decrypted.resize(len + final_len);
  EVP_CIPHER_CTX_free(ctx);
  return string(decrypted.begin(), decrypted.end());
}

//-----RSA шифрование ключа с EVP pkey

vector<unsigned char> rsa_encrypt_key(const string& pub_key_pem, const vector<unsigned char>& data){
	BIO* bio = BIO_new_mem_buf(pub_key_pem.data(), (int)pub_key_pem.size());
	EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	if(!pubkey) throw runtime_error("failed to load pub key");

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
	if(!ctx){
		EVP_PKEY_free(pubkey);
		throw runtime_error("PKEY new failed"); 
	}

	if(EVP_PKEY_encrypt_init(ctx) <= 0){
		EVP_PKEY_free(pubkey);
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("encrypt init failed");
	}

	if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){
		EVP_PKEY_free(pubkey);
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("failed to set padding");
	}

	size_t outlen;

	if(EVP_PKEY_encrypt(ctx, nullptr, &outlen, data.data(), data.size()) <= 0){
		EVP_PKEY_free(pubkey);
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("determine buf lenght failed");
	}

	vector<unsigned char> out(outlen);
	if(EVP_PKEY_encrypt(ctx, out.data(), &outlen, data.data(), data.size()) <= 0){
		EVP_PKEY_free(pubkey);
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("encrypt PKEY failed");
	}

	out.resize(outlen);

	EVP_PKEY_free(pubkey);
	EVP_PKEY_CTX_free(ctx);

	return out;
}

//-----RSA расшифрование ключа с EVP pkey

vector<unsigned char> rsa_decrypt_key(EVP_PKEY* privkey, const vector<unsigned char>& encrypted){
	if (!privkey) {
		cout << "ahuet" << endl;
    	throw runtime_error("private key is null!");
	}
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
	if(!ctx){
		throw runtime_error("PKEY new failed"); 
	}

	if(EVP_PKEY_decrypt_init(ctx) <= 0){
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("decrypt init failed");
	}

	if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("failed to set padding");
	}

	size_t outlen;
	if(EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted.data(), encrypted.size()) <= 0){
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("determine buf lenght failed");
	}

	vector<unsigned char> out(outlen);
	if(EVP_PKEY_decrypt(ctx, out.data(), &outlen, encrypted.data(), encrypted.size()) <= 0){
		EVP_PKEY_CTX_free(ctx);
		throw runtime_error("decrypt PKEY failed");
	}

	out.resize(outlen);

	EVP_PKEY_CTX_free(ctx);
	return out;
}

string base64Encode(const vector<unsigned char>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // Не вставлять новые строки
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

vector<unsigned char> base64Decode(const string& b64input) {
    BIO *bio, *b64;
    int decodeLen = b64input.size();
    vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(b64input.data(), decodeLen);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int totalRead = 0;
    int bytesRead = 0;
    while ((bytesRead = BIO_read(bio, buffer.data() + totalRead, decodeLen - totalRead)) > 0) {
        totalRead += bytesRead;
    }

    buffer.resize(totalRead);
    BIO_free_all(bio);
    return buffer;
}

void Exit(int sig) {
    close(client_socket);
    exit(0);

}

int main()
{
	EVP_PKEY* my_keys = Generate_RSA_keypair();
	string my_pubkey = Get_Public_Key_Pem(my_keys);
	string my_privkey = Get_Private_Key_Pem(my_keys);
	map<string, string> public_key_cache;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (client_socket == -1) {
        cerr << "Произошла ошибка создания сокета" << endl;
        return 1;
    }

    signal(SIGINT, Exit);

    sockaddr_in server_addr; // структура для доступа к сокету

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080); //приводим 8080 к сетевому порядку байт
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(client_socket, (sockaddr*)&server_addr, sizeof(server_addr))) {
        cerr << "Произошла ошибка\n";
        close(client_socket);
        return 1;
    }

	cout << "Успешное подключение к серверу!\n";

	while(true){
		string login;
		cout << "Введите имя пользователя: ";
		getline(cin, login);
		login = "registeruser:"+login+"\n";
		cout << endl;

		if (send(client_socket, login.c_str(), login.size(), 0) <= 0) {
			cerr << "Произошла ошибка отправки";
			return 1;
		}

		char buff[1024] = { 0 };
		int recievedBytes = recv(client_socket, buff, sizeof(buff) - 1, 0);
		if (recievedBytes <= 0) {
			cerr << "Ошибка получения от сервера\n";
		return 1;
}
		buff[recievedBytes] = '\0';
		string recieved = buff;

		if(recieved.rfind("logerror:") != 0){
			break;
		}

		cout<< recieved.substr(9) << endl;
	}

	cout << "Обмен ключами...\n";

	string my_pubkey_64 = base64Encode(vector<unsigned char>(my_pubkey.begin(), my_pubkey.end()));
	string KeyMessage = "storekey:" + my_pubkey_64+"\n";
	if (send(client_socket, KeyMessage.c_str(), KeyMessage.size(), 0) <= 0) {
		cerr << "Произошла ошибка отправки";
		return 1;
	}

	cout << "Успешный обмен ключами...\n";

	if (pipe(pipefd) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

    pid_t pid = fork();

    if (pid == -1) {
        cerr << "Произошла ошибка создания порта\n";
        close(client_socket);
        return 1;
    }

    if (pid == 0) { // дочерний процесс - отправка
        string message;
		close(pipefd[1]);
        while (true) {
            getline(cin, message);
            if (message.empty()) continue; // пустые строки просто игнорируем
			
			size_t colon = message.find(":");
			if (colon != string::npos) {
				string To = Trim(message.substr(0, colon));
				string Text = Trim(message.substr(colon + 1));

				if (To == "registeruser"){
					cout << "Вы уже зарегестрированы" << endl;
					continue;
				}
				else if(To == "a"){
					message+="\n";
					if (send(client_socket, message.c_str(), message.size(), 0) <= 0) {
                		cerr << "Произошла ошибка отправки";
                		break;
            		}
				}
				else{
					string recipient_pubkey;
					if(public_key_cache.count(recipient_pubkey))
						recipient_pubkey = public_key_cache[To];
					else{
						string req = "getkey:" + To +"\n";
						send(client_socket, req.c_str(), req.size(), 0);
						char keybuff[4096];
						int keylen = read(pipefd[0], keybuff, sizeof(keybuff) - 1);
						if(keylen <= 0){
							cerr<<"Ошибка получения ключа\n";
							continue;
						}
						keybuff[keylen] = '\0';

						vector<unsigned char> decoded = base64Decode(keybuff);
						string response(decoded.begin(), decoded.end());
						if (response.find("BEGIN PUBLIC KEY") == string::npos){
							cout << "Такого пользователя нет" << endl;
							continue;
						}
						recipient_pubkey = response;
						public_key_cache[To] = recipient_pubkey;
					}
					vector<unsigned char> aes_key = Generate_AES_Key();
					vector<unsigned char> ciphertext = AES_Encrypt(aes_key, Text);
					vector<unsigned char> encrypted_key = rsa_encrypt_key(recipient_pubkey, aes_key);

					string msg_to_send = To + ":" + base64Encode(encrypted_key) + ":" + base64Encode(ciphertext)+"\n";
					send(client_socket, msg_to_send.c_str(), msg_to_send.size(), 0);
				}


			}
        }
        close(client_socket);
        exit(0);
    }
    else { // родительский проесс - получение
		close(pipefd[0]);
        while (true) {
            char buff[1024] = { 0 };
            int recievedBytes = recv(client_socket, buff, sizeof(buff) - 1, 0);

            if (recievedBytes <= 0) {
                if (recievedBytes == 0) {
                    cout << "Сервер закрыл соединение \n";
                }
                else {
                    cerr << "Произошла ошибка получения данных \n";
                }

                kill(pid, SIGTERM);
                break;
            }

            buff[recievedBytes] = '\0';
            string recieved = buff;

			static string key_buffer;
			
			if(recieved.rfind("keyreply:", 0) == 0) {
				string base64key = recieved.substr(9); 
				write(pipefd[1], base64key.c_str(), base64key.size());
				continue;
			}

			cout << endl;

			size_t d1 = recieved.find(":");
			size_t d2 = recieved.find(":", d1+1);

			if(d1 == string::npos || d2 == string::npos){
				cout << recieved << endl;
				continue;
			}

			string sender = recieved.substr(0, d1); 
			string b64_encrypted_key = recieved.substr(d1+1, d2-d1-1); 
			string b64_encrypted_msg = recieved.substr(d2+1); 

			vector<unsigned char> encrypted_key = base64Decode(b64_encrypted_key);
			vector<unsigned char> encrypted_msg = base64Decode(b64_encrypted_msg);
			vector<unsigned char> aes_key;

			try{
				aes_key = rsa_decrypt_key(my_keys, encrypted_key);
			}
			catch(...){
				cout << "Не удалось расшифровать ключ" << endl;
				continue;
			}

			string decrypted;
			try{
				decrypted = AES_Decrypt(aes_key, encrypted_msg);
			}
			catch(...){
				cout << "Не удалось расшифровать полученое сообщение" << endl;
				continue;
			}

			cout << "[" << sender << "]:" << decrypted << endl; 
			cout << endl;

        }
        close(client_socket);
    }

    return 0;
}