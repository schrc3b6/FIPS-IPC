#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <string>
#include "common.h"
#include <getopt.h>
#include <iostream>
#include <unistd.h>

extern "C" {
    #include "blacklist_adapter.h"
}

using std::string;
using std::cout;
using std::endl;

static const struct option long_options[] = {
	{"add",		no_argument,		NULL, 'a' },
	{"del",		no_argument,		NULL, 'd' },
    {"ip",		required_argument,	NULL, 'i' },
    {"net", required_argument, NULL, 'n'},
    {"help", no_argument, NULL, 'h'},
	{0, 0, NULL,  0 }
};

void printUsage() {
	printf("Documentation: local tool for managing ip addresses in blacklist of katran-blocker\n");
	printf("\n");
	printf("Usage:\n");
	printf("    local-ip-manager --COMMAND [ --OPTIONS ]\n");
    printf("      COMMAND := { add | del | | help }\n");
    printf("      OPTIONS := { ip <ip-address> | net <subnet-address> }\n");
    printf("\n");
    printf("Example: local-ip-manager --add --ip 1.2.3.4\n");
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

    // perform requested action
    if (action == 1) { // action: add IP to blacklist
        struct in_addr addr4;
        struct in6_addr addr6;

        if (inet_pton(AF_INET, ip_string.c_str(), &addr4) == 1) { // IPv4
            if (subnet) {
                fprintf(stderr, "Error: Adding a subnet to blacklist only for IPv6 addresses.");
                exit(EXIT_FAIL_IP);
            }

            int fd_blacklist;
            int res;

            // block IPv4
            fd_blacklist = open_bpf_map(file_blacklist_ipv4);
            res = blacklist_modify(fd_blacklist, ip_string.data(), 1, 4); // 1 == add
            close(fd_blacklist);

            // error handling of unexpected result
            if (res != 0) {
                cout << "Adding " << ip_string << " to blockmap unsuccessful. Function blacklist_modify failed." << endl;
                return res;
            }

            cout << "Successfully added " << ip_string << " to blockmap." << endl;
            return res;
        } else if (inet_pton(AF_INET6, ip_string.c_str(), &addr6) == 1) { // IPv6
            if (subnet) {
                int fd_cache, fd_blacklist;
                int res;
                bool blacklist_modified = false;

                // block IPv6 subnet
                fd_cache = open_bpf_map(file_blacklist_ipv6_subnetcache);
                fd_blacklist = open_bpf_map(file_blacklist_ipv6_subnet);
                res = blacklist_subnet_modify(fd_cache, fd_blacklist, ip_string.data(), ACTION_ADD, &blacklist_modified);
                close(fd_cache);
                close(fd_blacklist);

                // error handling of unexpected result
                if (res != 0) {
                    cout << "Adding " << ip_string << "/64 to cache and/or blacklist unsuccessful. Function blacklist_subnet_modify failed." << endl;
                    return res;
                }

                cout << "Successfully increased subnet cache count of " << ip_string << "/64." << endl;
                if (blacklist_modified) {
                    cout << "Additionally, supplied IP was added to subnet blockmap." << endl;
                }
                return res;
            } else {
                int fd_blacklist;
                int res;

                // block IPv6
                fd_blacklist = open_bpf_map(file_blacklist_ipv6);
                res = blacklist_modify(fd_blacklist, ip_string.data(), 1, 6); // 1 == add
                close(fd_blacklist);

                // error handling of unexpected result
                if (res != 0) {
                    cout << "Adding " << ip_string << " to blockmap unsuccessful. Function blacklist_modify failed." << endl;
                    return res;
                }

                cout << "Successfully added " << ip_string << " to blockmap." << endl;
                return res;
            }
        } else {
            fprintf(stderr, "Error: IP address is not valid IPv4 nor IPv6: %s\n", ip_string.c_str());
            exit(EXIT_FAIL_IP);
        }
    } else if (action == 2) { // action: delete IP from blacklist
        struct in_addr addr4;
        struct in6_addr addr6;

        if (inet_pton(AF_INET, ip_string.c_str(), &addr4) == 1) {
            int fd_blacklist;
            int res;

            // unblock IPv4
            fd_blacklist = open_bpf_map(file_blacklist_ipv4);
            res = blacklist_modify(fd_blacklist, ip_string.data(), 2, 4); // 2 == delete
            close(fd_blacklist);

            // error handling of unexpected result
            if (res != 0) {
                cout << "Deleting " << ip_string << " from blockmap unsuccessful. Function blacklist_modify failed." << endl;
                return res;
            }

            cout << "Successfully deleted " << ip_string << " from blockmap." << endl;
            return res;
        } 
        else if (inet_pton(AF_INET6, ip_string.c_str(), &addr6) == 1) {
            if (subnet) {
                int fd_cache, fd_blacklist;
                int res;
                bool blacklist_modified = false;

                // unblock IPv6 subnet
                fd_cache = open_bpf_map(file_blacklist_ipv6_subnetcache);
                fd_blacklist = open_bpf_map(file_blacklist_ipv6_subnet);
                res = blacklist_subnet_modify(fd_cache, fd_blacklist, ip_string.data(), ACTION_DEL, &blacklist_modified);
                close(fd_blacklist);
                close(fd_cache);

                // error handling of unexpected result
                if (res != 0) {
                    cout << "Deleting " + ip_string + "/64 from blockmap unsuccessful. Function blacklist_subnet_modify failed." << endl;
                    return res;
                }

                cout << "Successfully decreased subnet cache count of " << ip_string <<  "/64." << endl;
                if (blacklist_modified) {
                    cout << "Additionally, supplied IP was removed from subnet blockmap." << endl;
                }
                return res;
            } else {
                int fd_blacklist;
                int res;

                // unblock IPv6
                fd_blacklist = open_bpf_map(file_blacklist_ipv6);
                res = blacklist_modify(fd_blacklist, ip_string.data(), ACTION_DEL, 6);
                close(fd_blacklist);

                // error handling of unexpected result
                if (res != 0) {
                    cout << "Deleting " << ip_string << " from blockmap unsuccessful. Function blacklist_modify failed." << endl;
                    return res;
                }

                cout << "Successfully deleted " << ip_string << " from blockmap." << endl;
                return res;
            }
        } else {
            fprintf(stderr, "Error: IP address is not valid IPv4 nor IPv6: %s\n", ip_string.c_str());
            exit(EXIT_FAIL_IP);
        }
    } 

    return 0;
}
