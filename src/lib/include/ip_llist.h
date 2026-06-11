/**
 *  Simple linked list to store IPv4 and IPv6 addresses with a corresponding timestamp
 * 
 *  
 * 
*/
#pragma once

#ifndef _IP_LLIST_H
#define _IP_LLIST_H
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>

#define IP_LLIST_SUCCESS (0) // Success return code
#define IP_LLIST_ARG_ERR (-1) // Error type for invalid argument errors
#define IP_LLIST_NULLPTR_ERR (-2) // Error type for nullpointer error
#define IP_LLIST_MEM_ERR (-3) // Error type for memory allocation failures 
#define IP_LLIST_MUTEX_ERR (-4) // Error type for mutex failures



// Struct for a single node in the list
struct ip_listnode_t
{
    void * key;
    time_t timestamp;
    int domain;
    struct ip_listnode_t * next;
};

// Struct for the linked list
struct ip_llist_t
{
    struct ip_listnode_t * head;
    pthread_mutex_t lock;
};


/*
    Initialises memory for the ip_llist_t struct (Should be called before entering the multi-threaded context)
*/
int ip_llist_init(struct ip_llist_t ** llist);

/*
    Adds a new node with addr and timestamp to the start of the list (thread safe)
*/
int ip_llist_push(struct ip_llist_t * llist, void * addr, time_t * timestamp, int domain);

/*
    Removes a node from the list (Not MT safe if called on the tail node)
*/
int ip_llist_remove(struct ip_listnode_t ** node, struct ip_listnode_t * prev);

/*
    Frees memory for the ip_llist_t struct (Should be called after exeting the multi-threaded context)
*/
int ip_llist_destroy(struct ip_llist_t ** llist);


#endif