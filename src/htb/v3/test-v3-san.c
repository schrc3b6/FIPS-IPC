#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>
#include "ip_hashtable.h"

#define THREAD_COUNT 5

void *thread_func_insert(void *arg) {
    struct ip_hashtable_t *htable = (struct ip_hashtable_t *)arg;
    struct in_addr ipv4;
    ipv4.s_addr = inet_addr("192.168.1.1");
    time_t now = time(NULL);
    ip_hashtable_insert(htable, &ipv4, AF_INET, now);
    return NULL;
}

void *thread_func_remove(void *arg) {
    struct ip_hashtable_t *htable = (struct ip_hashtable_t *)arg;
    struct in_addr ipv4;
    ipv4.s_addr = inet_addr("192.168.1.1");
    ip_hashtable_remove(htable, &ipv4, AF_INET);
    return NULL;
}

void *thread_func_set(void *arg) {
    struct ip_hashtable_t *htable = (struct ip_hashtable_t *)arg;
    struct in_addr ipv4;
    ipv4.s_addr = inet_addr("192.168.1.1");
    time_t now = time(NULL);
    ip_hashtable_set(htable, &ipv4, AF_INET, 5, now);
    return NULL;
}

int main() {
    struct ip_hashtable_t *htable;
    ip_hashtable_init(&htable, 60);

    pthread_t threads[THREAD_COUNT];

    // Create threads to test insertions
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_create(&threads[i], NULL, thread_func_insert, htable);
    }

    // Join threads
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(threads[i], NULL);
    }

    // Create threads to test removals
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_create(&threads[i], NULL, thread_func_remove, htable);
    }

    // Join threads
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(threads[i], NULL);
    }

    // Create threads to test updates
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_create(&threads[i], NULL, thread_func_set, htable);
    }

    // Join threads
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(threads[i], NULL);
    }

    ip_hashtable_destroy(&htable);
    return 0;
}

