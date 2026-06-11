#include "client_implementation.cc"

int main(int argc, char* argv[]) {
    InterventionClient client(
        initClient()
    );  

    string ipv4batch[] = {"1.2.3.4", "2.3.4.5", "3.4.5.6"};
    string ipv6batch[] = {"1:2:3::4", "2:3:4::5", "3:4:5::6"};
    size_t count = 3;
    string reply;

    reply = client.sendBlockRequestBatchv4(ipv4batch, count);
    cout << "Reply received: " << reply << endl;

    reply = client.sendUnblockRequestBatchv4(ipv4batch, count);
    cout << "Reply received: " << reply << endl;

    reply = client.sendBlockRequestBatchv6(ipv6batch, count);
    cout << "Reply received: " << reply << endl;

    reply = client.sendUnblockRequestBatchv6(ipv6batch, count);
    cout << "Reply received: " << reply << endl;

    return 0;
}