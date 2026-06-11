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

std::shared_ptr<Channel> initClient();

class InterventionClient {
public:
  InterventionClient(std::shared_ptr<Channel> channel)
      : stub_(Intervention::NewStub(channel)) {}

  BlockRequest *createBlockRequest();

  UnblockRequest *createUnblockRequest();

  template <typename RequestType>
  void addIpv4(RequestType &request, uint32_t ipv4) {
    auto ip = request.add_ip_address();
    ip->set_ipv4(&ipv4, 4);
  }

  // not using vec here to make it easier for c compatibility
  template <typename RequestType>
  void addIpv6(RequestType &request, uint8_t *ipv6) {
    auto ip = request.add_ip_address();
    ip->set_ipv6(ipv6, 16);
  }

  string sendBlockRequest(std::unique_ptr<BlockRequest> request);

  string sendUnblockRequest(std::unique_ptr<UnblockRequest> request);

  string sendStatusRequest(string backendName);

  string sendListRequest(string backendName);

private:
  std::unique_ptr<Intervention::Stub> stub_;
};
