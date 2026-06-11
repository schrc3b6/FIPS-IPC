#include "client_wrapper.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    intervention_client_t *client = intervention_client_create();
    printf("Client was created.\n");

    const char *block_response = sendBlockRequestv4(client, "1.2.3.4");
    printf("Server response to block request: %s\n", block_response);
    const char *unblock_response = sendUnblockRequestv4(client, "1.2.3.4");
    printf("Server response to unblock request: %s\n", unblock_response);

    intervention_client_destroy(client);
    printf("Client was destroyed.\n");

    return 0;
}