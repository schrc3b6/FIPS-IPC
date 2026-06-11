#include "client_implementation.h"
#include <cstdlib>
#include "client_wrapper.h"


struct intervention_client {
    void *obj;
};


intervention_client_request_t getBlockRequest(intervention_client_t client){
    if (client == NULL) { return NULL; }

    InterventionClient* obj = static_cast<InterventionClient *>(client);
    return obj->createBlockRequest();
}

void deleteBlockRequest(intervention_client_request_t request){
  if (request != NULL)
    delete static_cast<BlockRequest *>(request);
  return;
}

intervention_client_request_t getUnblockRequest(intervention_client_t client){
    if (client == NULL) { return NULL; }

    InterventionClient *obj = static_cast<InterventionClient *>(client);
    return obj->createUnblockRequest();
}

void add_ipv4_to_request(intervention_client_t client, intervention_client_request_t request, uint32_t ipv4){
    if (client == NULL) { return; }
    if (request == NULL) { return; }

    InterventionClient *obj = static_cast<InterventionClient *>(client);
    obj->addIpv4(*static_cast<BlockRequest *>(request), ipv4);
}

void add_ipv6_to_request(intervention_client_t client, intervention_client_request_t request, uint8_t ipv6[16]){
    if (client == NULL) { return; }
    if (request == NULL) { return; }

    InterventionClient *obj = static_cast<InterventionClient *>(client);
    obj->addIpv6(*static_cast<BlockRequest *>(request), ipv6);
}

const char* sendBlockRequest(intervention_client_t client, intervention_client_request_t request){
    if (client == NULL) { return NULL; }
    if (request == NULL) { return NULL; }

    InterventionClient *obj = static_cast<InterventionClient *>(client);
    std::string result = obj->sendBlockRequest(std::unique_ptr<BlockRequest>(static_cast<BlockRequest *>(request)));
    return strdup(result.c_str());
}

const char* sendUnblockRequest(intervention_client_t client, intervention_client_request_t request){
    if (client == NULL) { return NULL; }
    if (request == NULL) { return NULL; }

    InterventionClient *obj = static_cast<InterventionClient *>(client);
    std::string result = obj->sendUnblockRequest(std::unique_ptr<UnblockRequest>(static_cast<UnblockRequest *>(request)));
    return strdup(result.c_str());
}

intervention_client_t intervention_client_create() {
    InterventionClient *obj;
    obj = new InterventionClient(initClient());
    return obj;
}

void intervention_client_destroy(intervention_client_t client) {
    if (client == NULL) { return; }
    delete static_cast<InterventionClient *>(client);
}
