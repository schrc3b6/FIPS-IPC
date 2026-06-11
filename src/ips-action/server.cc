#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server_context.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <fstream>

#include <grpcpp/grpcpp.h>
#include "intervention.grpc.pb.h"

extern "C" {
    #include "blacklist_adapter.h"
}

using std::string;
using std::cout;
using std::endl;

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using intervention::Intervention;
using intervention::BlockRequest;
using intervention::BlockReply;
using intervention::UnblockRequest;
using intervention::UnblockReply;
using intervention::StatusRequest;
using intervention::StatusReply;
using intervention::ListRequest;
using intervention::ListReply;

enum Maps {
    Blacklistv4,
    Blacklistv6,
    VerdictCnt,
    Blacklistv6Subnet,
    Blacklistv6SubnetCache
};

string readFile(const string& path) {
  std::ifstream file;
  file.open(path);
  string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

  return content;
}

string checkMap(Maps map) {
    string dummy; // dummy IP
    int fd,  res, res1, res2; // iptype,
    char *ip_string;
    const char* file;

    switch (map) {
        case Blacklistv4:
            file = file_blacklist_ipv4;
            // iptype = 4;
            dummy = "1.2.3.4";
            break;
        case Blacklistv6:
            file = file_blacklist_ipv6;
            // iptype = 6;
            dummy = "::1";
            break;
        case VerdictCnt:
            file = file_verdict;
            break;
        case Blacklistv6Subnet:
            file = file_blacklist_ipv6_subnet;
            dummy = "::";
            break;
        case Blacklistv6SubnetCache:
            file = file_blacklist_ipv6_subnetcache;
            dummy = "::";
            break;
        default:
            return "Fail";
    }

    fd = bpf_obj_get(file);
    if (fd < 0) {
        return "Fail";
    }
    close(fd);
    return "OK";

    // if (map == Blacklistv4 || map == Blacklistv6) {
    //     fd = open_bpf_map(file);
    //     ip_string = dummy.data();
    //     res1 = blacklist_modify(fd, ip_string, 1, iptype); // add
    //     res2 = blacklist_modify(fd, ip_string, 2, iptype); // del
    //     close(fd);
    //     if (res1 != 0 || res2 != 0) {
    //         return "Fail";
    //     }
    //     return "OK";
    // }

    // __u64 value = 0;
    
    // if (map == VerdictCnt) {
    //     __u32 verdict = XDP_DROP;
    //     fd = open_bpf_map(file);
    //     res = bpf_map_lookup_elem(fd, &verdict, &value);
    //     close(fd);
    //     if (res != 0) {
    //         return "Fail";
    //     }
    //     return "OK";
    // }


    // if (map == Blacklistv6Subnet || map == Blacklistv6SubnetCache) {
    //     unsigned __int128 ipv6;
    //     __u64 subnet_string;
    //     res = inet_pton(AF_INET6, dummy.data(), &ipv6);
    //     if (res <= 0) {
    //         if (res == 0) {
    //             fprintf(stderr,
    //                 "ERR: IPv6 \"%s\" not in presentation format\n",
    //                 ip_string);
    //         } else {
    //             perror("inet_pton");
    //         }
    //         return "Fail: inet_pton";
    //     }
    //     subnet_string = (__u64) ipv6; // subnet

    //     fd = open_bpf_map(file);
    //     res1 = bpf_map_update_elem(fd, &subnet_string, &value, BPF_NOEXIST);
    //     res2 = bpf_map_delete_elem(fd, &subnet_string);
    //     close(fd);
    //     if (res1 != 0 || res2 != 0) {
    //         return "Fail";
    //     }
    //     return "OK";
    // }

    // return "Fail";
}

// add all blocked IP addresses to reply message for specified blacklist map
// reply message takes IP addresses as a string list/array
void listMap(Maps map, ListReply* reply) {
    int fd;
    __u64 value;

    int nr_cpus = libbpf_num_possible_cpus();
    __u64 values[nr_cpus];

    switch (map) {
        case Blacklistv4: {
            fd = open_bpf_map(file_blacklist_ipv4);
            __u32 next_key, *key = NULL;
            

            while (bpf_map_get_next_key(fd, key, &next_key) == 0) {
                char ip_string[INET_ADDRSTRLEN] = {0};
                value = 0;

                if (!inet_ntop(AF_INET, &next_key, ip_string, sizeof(ip_string))) {
                    fprintf(stderr, "ERR: Cannot convert u32 IP:0x%X to IP-txt\n", next_key);
                    exit(EXIT_FAIL_IP);
                }
                reply->add_ipv4(ip_string);

                if (bpf_map_lookup_elem(fd, &next_key, values) != 0) {
		            fprintf(stderr,
			        "Error: bpf_map_lookup_elem failed key:0x%X, errno: %d\n, %s\n", next_key, errno, strerror(errno));
                }

                // Sum values from each CPU
                for (int i = 0; i < nr_cpus; i++) {
                    // printf("Value for cpu %d: %lld\n", i, values[i]);
                    value += values[i];
                }
                reply->add_ipv4count(value);

                key = &next_key;
            }

            close(fd);
            break;
        }
        case Blacklistv6: {
            fd = open_bpf_map(file_blacklist_ipv6);
            unsigned __int128 next_key, *key = NULL;
            
            while (bpf_map_get_next_key(fd, key, &next_key) == 0) {
                char ip_string[INET6_ADDRSTRLEN] = {0}; 
                value = 0;
    
                if (!inet_ntop(AF_INET6, &next_key, ip_string, sizeof(ip_string))) {
                    fprintf(stderr,
                    "ERR: Cannot convert u128 IP:0x%llX%llX to IP-txt\n", (__u64)next_key,(__u64)(next_key << 64));
                    exit(EXIT_FAIL_IP);
                }
                reply->add_ipv6(ip_string);

                if (bpf_map_lookup_elem(fd, &next_key, values) != 0) {
		            fprintf(stderr,
			        "Error: bpf_map_lookup_elem failed key:0x%llx, errno: %d\n, %s\n", (unsigned long long)next_key, errno, strerror(errno));
                }

                // Sum values from each CPU
                for (int i = 0; i < nr_cpus; i++) {
                    // printf("Value for cpu %d: %lld\n", i, values[i]);
                    value += values[i];
                }
                reply->add_ipv6count(value);

                key = &next_key;
            }
            close(fd);
            break;
        }
        case Blacklistv6Subnet: {
            fd = open_bpf_map(file_blacklist_ipv6_subnet);
            __u64 next_key, *key = NULL;
            unsigned __int128 key_ext;

            while (bpf_map_get_next_key(fd, key, &next_key) == 0) {
                char ip_string[INET6_ADDRSTRLEN] = {0}; 
                value = 0;
                key_ext = (unsigned __int128) next_key;
                // key_ext = key_ext << 64;

    
                /* Convert IPv6 addresses from binary to text form */
                if (!inet_ntop(AF_INET6, &key_ext, ip_string, sizeof(ip_string))) {
                    fprintf(stderr,
                "ERR: Cannot convert u64 IPv6subnet:0x%llX to IP-txt\n", next_key);
                    exit(EXIT_FAIL_IP);
                }
                reply->add_ipv6subnet(ip_string);

                if (bpf_map_lookup_elem(fd, &next_key, values) != 0) {
		            fprintf(stderr,
			        "Error: bpf_map_lookup_elem failed key:0x%llx, errno: %d\n, %s\n", next_key, errno, strerror(errno));
                }

                // Sum values from each CPU
                for (int i = 0; i < nr_cpus; i++) {
                    // printf("Value for cpu %d: %lld\n", i, values[i]);
                    value += values[i];
                }
                reply->add_ipv6subnetcount(value);

                key = &next_key;
            }
            close(fd);
            break;
        }
        default: {
            fprintf(stderr, "ERR: Unknown map file");
            exit(EXIT_FAIL_MAP_FILE);
        }
    }
}

class InterventionServiceImplementation final : public Intervention::Service {

    Status sendBlockRequest(
        ServerContext* context, 
        const BlockRequest* request, 
        BlockReply* reply
    ) override {

    #ifdef EBPF
        int fd_blacklist = open_bpf_map(file_blacklist_ipv4);
        int fd_blacklist6 = open_bpf_map(file_blacklist_ipv6);
        int res=0; bool error=false;
        // string ipv4Address = request->ip_address().data
        for (const intervention::IPAddress& entry : request->ip_address()) {
          if ( entry.has_ipv4()){
            res = blacklist_modify(fd_blacklist, (void*) entry.ipv4().data(), 1);
          }
          // message format allows for both ipv4 and ipv6 addresses
          if ( entry.has_ipv6()){
            res = blacklist_modify(fd_blacklist6, (void*) entry.ipv6().data(), 1);
          }
          if (res != 0) {
            error=true;
          }
        }
        // error handling of unexpected result
        if (error) {
            reply->set_message("Adding batch of IPv4 addresses to blockmap unsuccessful. Function blacklist_modify failed.");
            return Status::CANCELLED;
        }
#endif
        //cout << "received block request for" << request->ip_address_size() << endl;
        reply->set_message("Succesfully added batch of IPv4 addresses to blockmap.");
        return Status::OK;
    }

    Status sendUnblockRequest(
        ServerContext* context,
        const UnblockRequest* request,
        UnblockReply* reply
    ) override {
    #ifdef EBPF
        int fd_blacklist = open_bpf_map(file_blacklist_ipv4);
        int fd_blacklist6 = open_bpf_map(file_blacklist_ipv6);
        int res=0; bool error=false;
        // string ipv4Address = request->ip_address().data
        for (const intervention::IPAddress& entry : request->ip_address()) {
          if ( entry.has_ipv4()){
            res = blacklist_modify(fd_blacklist, (void*) entry.ipv4().data(), 2);
          }
          // message format allows for both ipv4 and ipv6 addresses
          if ( entry.has_ipv6()){
            res = blacklist_modify(fd_blacklist6, (void*) entry.ipv6().data(), 2);
          }
          if (res != 0) {
            error=true;
          }
        }
        // error handling of unexpected result
        if (error) {
            reply->set_message("Adding batch of IPv4 addresses to blockmap unsuccessful. Function blacklist_modify failed.");
            return Status::CANCELLED;
        }
#endif
        reply->set_message("Succesfully added batch of IPv4 addresses to blockmap.");
        return Status::OK;
    }

    Status sendStatusRequest(
        ServerContext* context,
        const StatusRequest* request,
        StatusReply* reply
    ) override {
        string backendName = request->backendname();
    #ifdef EBPF
        reply->set_message("Hello " + backendName + ", gRPC Server up and running.\n"
            + "\nLoad balancer:"
            + "\nStatus blacklistv4: " + checkMap(Blacklistv4) 
            + "\nStatus blacklistv6: " + checkMap(Blacklistv6)
            + "\nStatus verdict_cnt: " + checkMap(VerdictCnt)
            + "\nStatus blacklistv6subnet: " + checkMap(Blacklistv6Subnet)
            + "\nStatus blacklistv6subnetcache: " + checkMap(Blacklistv6SubnetCache)
            + "\n");
    #else
        reply->set_message("Hello " + backendName + ", gRPC Server up and running.\n");
    #endif
        return Status::OK;
    }

    Status sendListRequest(
        ServerContext* context,
        const ListRequest* request,
        ListReply* reply
    ) override {
        string backendName = request->backendname();
        reply->set_message("Hello " + backendName + ".\n");

#ifdef EBPF
        listMap(Blacklistv4, reply);
        listMap(Blacklistv6, reply);
        listMap(Blacklistv6Subnet, reply);
#endif
        return Status::OK;
    }
};

// authentication
grpc::SslServerCredentialsOptions getServerCredsOptions() {
    string root_cert = readFile("../cert/ca-cert.pem");
    string private_key = readFile("../cert/server-key.pem");
    string cert_chain = readFile("../cert/server-cert.pem");

    std::vector<grpc::SslServerCredentialsOptions::PemKeyCertPair> key_cert_pair = {
        {
            private_key,
            cert_chain
        }
    };

    grpc::SslServerCredentialsOptions creds_options(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);

    // creds_options.force_client_auth = true; // deprecated!?
    creds_options.pem_root_certs = root_cert;
    creds_options.pem_key_cert_pairs = key_cert_pair;

    // old: only server-side TLS
    // grpc::SslServerCredentialsOptions creds_options(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);

    return creds_options;
}

void Run() {
    string address("0.0.0.0:5000");
    InterventionServiceImplementation service;

    ServerBuilder builder;

    builder.AddListeningPort(address, grpc::InsecureServerCredentials()); // old: insecure
    // builder.AddListeningPort(address, grpc::SslServerCredentials(getServerCredsOptions()));
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    cout << "Server listening on port: " << address << endl;

    server->Wait();
}

int main(int argc, char** argv) {
    Run();

    return 0;
}
