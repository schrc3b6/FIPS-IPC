#include "client_implementation.cc"

#include <getopt.h>

static const struct option long_options[] = {
	{"add",		no_argument,		NULL, 'a' },
	{"del",		no_argument,		NULL, 'd' },
    {"ip",		required_argument,	NULL, 'i' },
    {"net", required_argument, NULL, 'n'},
    {"status", no_argument, NULL, 's'},
    {"list",	no_argument,		NULL, 'l' },
    {"help", no_argument, NULL, 'h'},
	{0, 0, NULL,  0 }
};

void printUsage() {
	printf("Documentation: ips-action gRPC tool for configuring blacklist of katran-blocker\n");
	printf("\n");
	printf("Usage:\n");
	printf("    client --COMMAND [ --OPTIONS ]\n");
    printf("      COMMAND := { add | del | status | list | help }\n");
    printf("      OPTIONS := { ip <ip-address> | net <subnet-address> }\n");
    printf("\n");
    printf("Example: client --add --ip 1.2.3.4\n");
    printf("Commands add and delete need an option.\n");
    printf("Option net only works with an IPv6 subnet, provided as a full IPv6 address.\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    int opt;
    unsigned int action = 0;
    unsigned int subnet = 0;
    int longindex = 0;
    string ip_string;

    #define STR_MAX 40 // trivial input validation?

    // parse all command line arguments
    while ((opt = getopt_long(argc, argv, "adi", long_options, &longindex)) != -1) {
        switch (opt) {
            case 'a': // add
                action = 1;
                break;
            case 'd': // delete
                action = 2;
                break;
            case 'n': // subnet argument for add/delete
                // TODO
                subnet = 1;
                [[fallthrough]];
            case 'i': // ip argument for add/delete
                if (!optarg || strlen(optarg) >= STR_MAX) { // check STR_MAX again
                    printf("Error: source IP too long or NULL\n");
                    return EXIT_FAIL_IP;
                } else {
                    string s(optarg);
                    ip_string = s;
                    break;
                }
            case 's': // status
                action = 3;
                break;
            case 'l': // list
                action = 4;
                break;
            case 'h': // help
            default:
                printUsage();
                return EXIT_FAIL_OPTION;
        }
    }

    if (action == 0) {
        printUsage();
        return EXIT_FAIL_OPTION;
    }

    
    // create client and establish connection
    InterventionClient client(
        initClient()
    );

    // WARNING - old: create client with insecure channel creation
    // InterventionClient client(
    //     grpc::CreateChannel(
    //         address, 
    //         grpc::InsecureChannelCredentials()
    //     )
    // );


    string reply;

    // perform requested action / call RPC
    if (action == 1) { // action: add IP to blacklist
        struct in_addr addr4;
        struct in6_addr addr6;

        if (inet_pton(AF_INET, ip_string.c_str(), &addr4) == 1) { // IPv4
            if (subnet) {
                fprintf(stderr, "Error: Adding a subnet to blacklist only for IPv6 addresses.");
                exit(EXIT_FAIL_IP);
            }
            reply = client.sendBlockRequestv4(ip_string);
            cout << "Reply received: " << reply << endl;
        } else if (inet_pton(AF_INET6, ip_string.c_str(), &addr6) == 1) { // IPv6
            if (subnet) {
                reply = client.sendBlockRequestSubnet(ip_string);
            } else {
                reply = client.sendBlockRequestv6(ip_string);
            }
            cout << "Reply received: " << reply << endl;
        } else {
            fprintf(stderr, "Error: IP address is not valid IPv4 nor IPv6: %s\n", ip_string.c_str());
            exit(EXIT_FAIL_IP);
        }
    } else if (action == 2) { // action: delete IP from blacklist
        struct in_addr addr4;
        struct in6_addr addr6;

        if (inet_pton(AF_INET, ip_string.c_str(), &addr4) == 1) {
            reply = client.sendUnblockRequestv4(ip_string);
            cout << "Reply received: " << reply << endl;
        } 
        else if (inet_pton(AF_INET6, ip_string.c_str(), &addr6) == 1) {
            if (subnet) {
                reply = client.sendUnblockRequestSubnet(ip_string);
            } else {
                reply = client.sendUnblockRequestv6(ip_string);
            }
            cout << "Reply received: " << reply << endl;
        } else {
            fprintf(stderr, "Error: IP address is not valid IPv4 nor IPv6: %s\n", ip_string.c_str());
            exit(EXIT_FAIL_IP);
        }
    } else if (action == 3) { // action: get status from load balancer
        char hostname[16];
        gethostname(hostname, 16);
        
        string backendName(hostname);
        reply = client.sendStatusRequest(backendName);
        cout << "Reply received: " << reply << endl;
    } else if (action == 4) { // action: get list of blacklisted IPs from load balancer
        char hostname[16];
        gethostname(hostname, 16);

        string backendName(hostname);
        reply = client.sendListRequest(backendName);
        cout << "Reply received: " << reply << endl;
    } 

    return 0;
}
