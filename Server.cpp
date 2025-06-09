#include <iostream>
#include <string>
#include <cstring>
#include <csignal>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h> 
#include <netinet/in.h>

using namespace std;

int server_socket;
fd_set master_set;

class client;
client* clientsHead = nullptr;

class client {
public:
    string login;
    int socket;
    bool IsRegistered = false;
    client* nextClient = nullptr;
    string public_key_pem;
    string buffer;

    client(int _socket) {
        this->socket = _socket;
        this->nextClient = clientsHead;
        clientsHead = this;
    }

    ~client() {
        if (clientsHead == this) {
            clientsHead = this->nextClient;
        }
        else {
            client* prevClient = clientsHead;
            while (prevClient && prevClient->nextClient != this) prevClient = prevClient->nextClient;
            if (prevClient) prevClient->nextClient = this->nextClient;
        }
    }

    static client* Get_Client_By_login(const string& login) {
        client* curClient = clientsHead;
        while (curClient)
        {
            if (curClient->login == login) return curClient;
            curClient = curClient->nextClient;
        }
        return nullptr; //не нашли клиента с таким логином
    }

    static client* Get_Client_By_Socket(int socket) {
        client* curClient = clientsHead;
        while (curClient)
        {
            if (curClient->socket == socket) return curClient;
            curClient = curClient->nextClient;
        }
        return nullptr; //не нашли клиента с таким сокетом
    }

};

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

void Get_Users(int Exception = -1) {
    string message = "Список клиентов  в сети:\n";
    send(Exception, message.c_str(), message.size(), 0);
    client* curClient = clientsHead;
    while (curClient)
    {
        if (curClient->IsRegistered && curClient->socket != Exception) {
            string message = curClient->login + "\n";
            send(Exception, message.c_str(), message.size(), 0);
        }
        curClient = curClient->nextClient;
    }
}

void Stream_Message(const string& message, int exception = -1) { //широковещательный
    client* curClient = clientsHead;
    while (curClient) {
        if (curClient->IsRegistered && curClient->socket != exception)
            send(curClient->socket, message.c_str(), message.size(), 0);
        curClient = curClient->nextClient;
    }
}

void Check_Message(client* c, const string& message) {
    if (message.rfind("getusers:", 0) == 0) {
        Get_Users(c->socket);
    }
    else if (message.rfind("registeruser:", 0) == 0 && !(c->IsRegistered)) {
        string newlogin = Trim(message.substr(13));
        if (!client::Get_Client_By_login(newlogin)) {
            c->login = newlogin;
            c->IsRegistered = true;
            string RegMessage = "Вы зарегестрировались в системе под никнеймом: " + newlogin + "\n";
            send(c->socket, RegMessage.c_str(), RegMessage.size(), 0);

            string JoinMessage = "Пользователь под ником " + newlogin + " присоединился к чату\n";
            Stream_Message(JoinMessage, c->socket);
            cout << newlogin << " подключён\n" << endl;
        }
        else {
            string TakenloginMessage = "logerror:Извините, но никнейм " + newlogin + " уже занят\n";
            send(c->socket, TakenloginMessage.c_str(), TakenloginMessage.size(), 0);
        }
    }
    else if (!c->IsRegistered) {
        string NotRegUserMessage = "Сперва зарегестрируйтесь командой registeruser:<ваш логин>\n";
        send(c->socket, NotRegUserMessage.c_str(), NotRegUserMessage.size(), 0);
    }
    else if (message.rfind("storekey:", 0) == 0) {
        string key = Trim(message.substr(9));
        c->public_key_pem = key;
    }
    else if (message.rfind("getkey:", 0) == 0) {
        string target_login = Trim(message.substr(7));
        client* target = client::Get_Client_By_login(target_login);
        if (target && !target->public_key_pem.empty()) {
            string reply = "keyreply:" + target->public_key_pem;
            send(c->socket, reply.c_str(), reply.size(), 0);
        }
        else {
            string err = "keyreply:";
            send(c->socket, err.c_str(), err.size(), 0);
        }
    }
    else {
        if (message.rfind("a:", 0) == 0) {
            string textMessage = Trim(message.substr(2));
            string processedMessage = "[Всем от " + c->login + " ]: " + textMessage + "\n";
            Stream_Message(processedMessage, c->socket);
            cout << c->login << "(Всем): " << textMessage << endl;
        }
        else {
            size_t colon = message.find(":");
            if (colon != string::npos) {
                cout << "имитация перехвата сообщения по пути к серверу: " << message << endl;
                string To = Trim(message.substr(0, colon));
                client* recipient = client::Get_Client_By_login(To);
                string newmessage = c->login + message.substr(colon);
                if (recipient && recipient->IsRegistered) {
                    cout << "имитация перехвата сообщения по пути к пользователю: " << message << endl;
                    send(recipient->socket, newmessage.c_str(), newmessage.size(), 0);
                }
                else {
                    string Error = "Пользователь с никнеймом " + To + " не найден!\n";
                    send(c->socket, Error.c_str(), Error.size(), 0);
                }
            }
            else {
                string Error = "команда не найдена\n";
                send(c->socket, Error.c_str(), Error.size(), 0);
            }

        }
    }
}

void Check_Client_Data(client* c) {
    char buff[1024];
    int len = recv(c->socket, buff, sizeof(buff), 0);
    if (len <= 0) {
        cout << (c->IsRegistered ? c->login : to_string(c->socket)) << " не в сети" << endl;
        if (c->IsRegistered) {
            string LeftMessage = c->login + " покинул чат\n";
            Stream_Message(LeftMessage, c->socket);
        }
        close(c->socket);
        FD_CLR(c->socket, &master_set);
        delete c;
    }
    else {
        c->buffer.append(buff, len);

        // обрабатываем сообщения до первой \n
        size_t pos;
        while ((pos = c->buffer.find('\n')) != string::npos) {
            string message = c->buffer.substr(0, pos);
            c->buffer.erase(0, pos + 1); // +1 чтобы убрать сам \n!!!!!!!!
            Check_Message(c, message); 
        }
    }
}

void Exit(int) {
    client* curClient = clientsHead;
    while (curClient) {
        close(curClient->socket);
        curClient = curClient->nextClient;
    }

    close(server_socket);
    exit(0);

}

int main()
{
    signal(SIGINT, Exit); //SIGINT - сигнал прерывания, обычно ctrl+c
    server_socket = socket(AF_INET, SOCK_STREAM, 0); // AF_INET - IPv4; SOCK_STREAM - TCP
    if (server_socket < 0) {
        cerr << "попытка создания сокета провалилась\n";
        return 1;
    }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr; // структура для доступа к сокету

    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080); //приводим 8080 к сетевому порядку байт
    addr.sin_addr.s_addr = INADDR_ANY; //слушаем все интерфейсы(любой ip на машине)

if (bind(server_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "Не удалось привязать сокет\n";
        return 1;
    }

    listen(server_socket, SOMAXCONN); //SOMAXCONN - макс. очередь подключений. начинаем слушать подключенияс
    cout << "Сервер запущен на порту 8080" << endl;

    FD_ZERO(&master_set);
    FD_SET(server_socket, &master_set);
    int Max_FD = server_socket;

    while (true) {
        fd_set read_fds = master_set; // копируем, чтобы не модифицировать случайно
        if (select(Max_FD + 1, &read_fds, nullptr, nullptr, nullptr) < 0) continue;

        for (int i = 0; i <= Max_FD; ++i) {
            if (!FD_ISSET(i, &read_fds)) continue; //если сокет активен пувкай ожидает других

            if (i == server_socket) {
                sockaddr_in client_addr;
                socklen_t len = sizeof(client_addr);
                int client_socket = accept(server_socket, (sockaddr*)&client_addr, &len);

                if (client_socket >= 0) {
                    client* new_Client = new client(client_socket);
                    FD_SET(client_socket, &master_set);
                    if (client_socket > Max_FD) Max_FD = client_socket;
                    cout << "Соединение: " << inet_ntoa(client_addr.sin_addr) << endl; //ip-addr в строку.
                }
            }
            else {
                client* client = client::Get_Client_By_Socket(i);
                if (client) Check_Client_Data(client);
            }
        }
    }

    return 0;
}