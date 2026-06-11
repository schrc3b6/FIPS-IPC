/**
 *  This is an auxiliary header file, that was originally meant to include
 *  different types of IPC libraries.
 * 
*/
#pragma once

#ifndef _IO_IPC_H
#define _IO_IPC_H
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

// Local includes
#include "shm_ringbuf.h"

// Error types
#define IO_IPC_SUCCESS (0)
#define IO_IPC_ARG_ERR (-1) // An argument outside of the allowed value range was provided
#define IO_IPC_MEM_ERR (-2) // Memory allocation failed
#define IO_IPC_NULLPTR_ERR (-3) // A null pointer was provided for a non optional argument 
#define IO_IPC_MUTEX_ERR (-4) // Unlocking or locking a mutex failed
#define IO_IPC_SIZE_ERR (-5) // Operation can not be concluded, due to a capacity maximum

#define PAGESIZE 4096

// IPC types
enum ipc_type_t 
{
    SHM,
    DISK,
    POSIX_IO,
    FIPS
};

#endif
