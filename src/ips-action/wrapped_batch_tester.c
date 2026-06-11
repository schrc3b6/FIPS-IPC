#include "client_wrapper.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    intervention_client_t *client = intervention_client_create();
    printf("Client was created.\n");

    const int count = 3;
    char* batch[] = {"1.2.3.4", "2.3.4.5", "3.4.5.6"}; 
    char* batch6[] = {"1:2:3::4", "2:3:4::5", "3:4:5::6"};
    
    const char *block_response = sendBlockRequestBatchv4(client, batch, count);
    printf("Server response to block request: %s\n", block_response);
    const char *unblock_response = sendUnblockRequestBatchv4(client, batch, count);
    printf("Server response to unblock request: %s\n", unblock_response);

    block_response = sendBlockRequestBatchv6(client, batch6, count);
    printf("Server response to block request: %s\n", block_response);
    unblock_response = sendUnblockRequestBatchv6(client, batch6, count);
    printf("Server response to unblock request: %s\n", unblock_response);

    intervention_client_destroy(client);
    printf("Client was destroyed.\n");

    return 0;
}