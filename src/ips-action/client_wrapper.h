#ifndef __GRPC_WRAPPER_H__
#define __GRPC_WRAPPER_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* intervention_client_t;
typedef void* intervention_client_request_t;

// client object
intervention_client_t intervention_client_create();
void intervention_client_destroy(intervention_client_t client);

// block methods
intervention_client_request_t getBlockRequest(intervention_client_t client);
void deleteBlockRequest(intervention_client_request_t request);
intervention_client_request_t getUnblockRequest(intervention_client_t client);
void add_ipv4_to_request(intervention_client_t client, intervention_client_request_t request, uint32_t ipv4);
void add_ipv6_to_request(intervention_client_t client, intervention_client_request_t request, uint8_t ipv6[16]);
const char* sendBlockRequest(intervention_client_t client, intervention_client_request_t request);
const char* sendUnblockRequest(intervention_client_t client, intervention_client_request_t request);

#ifdef __cplusplus
}
#endif

#endif /* __GRPC_WRAPPER_H__ */
