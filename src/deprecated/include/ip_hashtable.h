/**
 *  Simple thread-safe hashtable to store IPv4 and IPv6 Addresses
 *  and a related counter value.
 * 
*/
#pragma once

#ifndef _IP_HASHTABLE
#define _IP_HASHTABLE

#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <spooky-c.h>

// Number of binds used by the hashtable
#define NBINS 600011

#define IP_HTABLE_SUCCESS (0) // Success return code
#define IP_HTABLE_ARG_ERR (-1) // Argument passed is not within allowed value range
#define IP_HTABLE_NULLPTR_ERR (-2) // Nullpointer was passed as argument
#define IP_HTABLE_MEM_ERR (-3) // Memory allocation failed 
#define IP_HTABLE_MUTEX_ERR (-4) // Mutex lock or unlock failed
#define IP_HTABLE_NOEXIST (-5) // Entry does not exist 

// Struct to store a single hashtable entry
struct ip_hashbin_t
{ 
   void * key;
   int domain;
   uint32_t count;
   pthread_mutex_t lock;
   struct ip_hashbin_t * next;

};

// Struct to represent the entire hashtable
struct ip_hashtable_t {

    struct ip_hashbin_t hbins[NBINS];
};

/*
    Initialises memory for the ip_hashtable_t struct (Should be called before entering multi-threaded context)
    On error, a error code < 0 is returned (see top)
*/
int ip_hashtable_init(struct ip_hashtable_t ** htable);

/*
    Inserts an ip address pointed to by key into the hashtable and returns its count on success (> 1 for already present addresses) 
    Domain has to be specified as AF_INET for IPv4 or AF_INET6 for IPv6. On error, a error code < 0 is returned (see top)
*/
int ip_hashtable_insert(struct ip_hashtable_t * htable, void * key, int domain);

/*
    Removes the address pointed to by key from the table. Returns the count for the address on success.
    Domain has to be specified as AF_INET for IPv4 or AF_INET6 for IPv6. On error, a error code < 0 is returned (see top)
*/
int ip_hashtable_remove(struct ip_hashtable_t * htable, void * key, int domain);

/*
    Sets the counter value for the  address pointed to by key. Returns the prior count for the address on success.
    Domain has to be specified as AF_INET for IPv4 or AF_INET6 for IPv6. On error, a error code < 0 is returned (see top)
    key has to present in the table, otherwise, IP_HTABLE_NOEXIST is returned
*/
int ip_hashtable_set(struct ip_hashtable_t * htable, void * key, int domain, uint32_t value);

/*
    Frees memory for the ip_hasttable_t struct (Should be called after exiting the multi threaded context)
    On error, a error code < 0 is returned (see top)
*/
int ip_hashtable_destroy(struct ip_hashtable_t ** htable); 

//inline uint32_t spooky_hash(void * src, uint8_t len);

#endif