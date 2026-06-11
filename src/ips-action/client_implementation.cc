#include "client_implementation.h"
#include <arpa/inet.h>
#include <cstdint>
#include <fstream>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <netinet/in.h>
#include <string>

#include "intervention.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <unistd.h>

#include "common.h"

using std::cout;
using std::endl;
using std::string;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using intervention::BlockReply;
using intervention::BlockRequest;
using intervention::Intervention;
using intervention::ListReply;
using intervention::ListRequest;
using intervention::StatusReply;
using intervention::StatusRequest;
using intervention::UnblockReply;
using intervention::UnblockRequest;

string errorMessage(Status status) {
  cout << status.error_code() << ": " << status.error_message() << endl;
  return "RPC failed";
}

string readFile(const string &path) {
  std::ifstream file;
  file.open(path);
  string content((std::istreambuf_iterator<char>(file)),
                 std::istreambuf_iterator<char>());

  return content;
}

// init connection to server with TLS authentication
std::shared_ptr<Channel> initClient() {
  const char *lb_ip;
  string env_name = "LB_IP_ADDRESS";
  lb_ip = getenv(env_name.c_str());
  if (lb_ip == NULL) {
    cout << "Warning: Environment variable for load balancer's IP "
            "(LB_IP_ADDRESS) is not defined, using localhost instead."
         << endl
         << endl;
    string lo = "0.0.0.0";
    lb_ip = lo.c_str();
  }
  string lb_ip_string(lb_ip);
  string address(lb_ip_string + ":5000");

  // channel creation with TLS authentication
  string root_cert = readFile("../cert/ca-cert.pem");
  string private_key = readFile("../cert/client-key.pem");
  string cert_chain = readFile("../cert/client-cert.pem");

  grpc::SslCredentialsOptions creds_options;
  creds_options.pem_root_certs = root_cert;
  creds_options.pem_private_key = private_key;
  creds_options.pem_cert_chain = cert_chain;
  auto channel_creds = grpc::SslCredentials(creds_options);
  // auto channel = grpc::CreateChannel(address, channel_creds);
  auto channel = grpc::CreateChannel( address, grpc::InsecureChannelCredentials());

  return channel;
}

BlockRequest *InterventionClient::createBlockRequest() {
  auto request = new BlockRequest();
  return request;
}

UnblockRequest *InterventionClient::createUnblockRequest() {
  auto request = new UnblockRequest();
  return request;
}


// void InterventionClient::addIpv4(UnblockRequest &request, uint32_t ipv4) {
//   auto ip = request.add_ip_address();
//   ip->set_ipv4(&ipv4, 4);
// }
//
// // not using vec here to make it easier for c compatibility
// void InterventionClient::addIpv6(UnblockRequest &request, uint8_t *ipv6) {
//   auto ip = request.add_ip_address();
//   ip->set_ipv6(ipv6, 16);
// }
//
// void InterventionClient::addIpv4(BlockRequest &request, uint32_t ipv4) {
//   auto ip = request.add_ip_address();
//   ip->set_ipv4(&ipv4, 4);
// }
//
// // not using vec here to make it easier for c compatibility
// void InterventionClient::addIpv6(BlockRequest &request, uint8_t *ipv6) {
//   auto ip = request.add_ip_address();
//   ip->set_ipv6(ipv6, 16);
// }


// template <typename RequestType>
// void InterventionClient::addIpv4(RequestType &request, uint32_t ipv4) {
//   auto ip = request.add_ip_address();
//   ip->set_ipv4(&ipv4, 4);
// }
//
// // not using vec here to make it easier for c compatibility
// template <typename RequestType>
// void InterventionClient::addIpv6(RequestType &request, uint8_t *ipv6) {
//   auto ip = request.add_ip_address();
//   ip->set_ipv6(ipv6, 16);
// }
//
string
InterventionClient::sendBlockRequest(std::unique_ptr<BlockRequest> request) {
  BlockReply reply;
  ClientContext context;

  Status status = stub_->sendBlockRequest(&context, *request, &reply);

  if (status.ok()) {
    return reply.message();
  } else {
    return errorMessage(status);
  }
}

string InterventionClient::sendUnblockRequest(
    std::unique_ptr<UnblockRequest> request) {
  UnblockReply reply;
  ClientContext context;

  Status status = stub_->sendUnblockRequest(&context, *request, &reply);

  if (status.ok()) {
    return reply.message();
  } else {
    return errorMessage(status);
  }
}

string InterventionClient::sendStatusRequest(string backendName) {
  StatusRequest request;
  StatusReply reply;
  ClientContext context;

  request.set_backendname(backendName);

  Status status = stub_->sendStatusRequest(&context, request, &reply);

  if (status.ok()) {
    return reply.message();
  } else {
    return errorMessage(status);
  }
}

string InterventionClient::sendListRequest(string backendName) {
  ListRequest request;
  ListReply reply;
  ClientContext context;

  request.set_backendname(backendName);

  Status status = stub_->sendListRequest(&context, request, &reply);

  if (status.ok()) {
    string list;

    list = reply.message();

    list += "\nBlacklist IPv4:\n";
    if (reply.ipv4_size() < 1) {
      list += "--None--\n";
    } else {
      for (int i = 0; i < reply.ipv4_size(); i++) {
        list += reply.ipv4(i);
        list += ": ";
        list += std::to_string(reply.ipv4count(i));
        list += "\n";
      }
    }
    list += "\nBlacklist IPv6:\n";
    if (reply.ipv6_size() < 1) {
      list += "--None--\n";
    } else {
      for (int i = 0; i < reply.ipv6_size(); i++) {
        list += reply.ipv6(i);
        list += ": ";
        list += std::to_string(reply.ipv6count(i));
        list += "\n";
      }
    }
    list += "\nBlacklist IPv6 subnet:\n";
    if (reply.ipv6subnet_size() < 1) {
      list += "--None--\n";
    } else {
      for (int i = 0; i < reply.ipv6subnet_size(); i++) {
        list += reply.ipv6subnet(i);
        list += "/64: ";
        list += std::to_string(reply.ipv6subnetcount(i));
        list += "\n";
      }
    }

    return list;
  } else {
    return errorMessage(status);
  }
}
