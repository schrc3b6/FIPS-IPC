#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include "ip_hashtable.h"

void test_ip_hashtable_init() {
    struct ip_hashtable_t *htable = NULL;
    int result = ip_hashtable_init(&htable, 60);
    assert(result == IP_HTABLE_SUCCESS);
    assert(htable != NULL);
    ip_hashtable_destroy(&htable);
}

void test_ip_hashtable_insert_and_count() {
    struct ip_hashtable_t *htable = NULL;
    ip_hashtable_init(&htable, 60);

    struct in_addr ipv4;
    inet_pton(AF_INET, "192.168.1.1", &ipv4);
    time_t now = time(NULL);

    int count = ip_hashtable_insert(htable, &ipv4, AF_INET, now);
    assert(count == 1);

    count = ip_hashtable_insert(htable, &ipv4, AF_INET, now);
    assert(count == 2);

    ip_hashtable_destroy(&htable);
}

void test_ip_hashtable_remove() {
    struct ip_hashtable_t *htable = NULL;
    ip_hashtable_init(&htable, 60);

    struct in_addr ipv4;
    inet_pton(AF_INET, "192.168.1.1", &ipv4);
    time_t now = time(NULL);

    ip_hashtable_insert(htable, &ipv4, AF_INET, now);
    int count = ip_hashtable_remove(htable, &ipv4, AF_INET);
    assert(count == 1);

    count = ip_hashtable_remove(htable, &ipv4, AF_INET);
    assert(count == IP_HTABLE_NOEXIST);

    ip_hashtable_destroy(&htable);
}

void test_ip_hashtable_set() {
    struct ip_hashtable_t *htable = NULL;
    ip_hashtable_init(&htable, 60);

    struct in_addr ipv4;
    inet_pton(AF_INET, "192.168.1.1", &ipv4);
    time_t now = time(NULL);

    ip_hashtable_insert(htable, &ipv4, AF_INET, now);
    int old_count = ip_hashtable_set(htable, &ipv4, AF_INET, 10, now);
    assert(old_count == 1);

    struct in_addr ipv4_nonexist;
    inet_pton(AF_INET, "192.168.1.2", &ipv4_nonexist);
    old_count = ip_hashtable_set(htable, &ipv4_nonexist, AF_INET, 10, now);
    assert(old_count == IP_HTABLE_NOEXIST);

    ip_hashtable_destroy(&htable);
}

int main() {
    test_ip_hashtable_init();
    test_ip_hashtable_insert_and_count();
    test_ip_hashtable_remove();
    test_ip_hashtable_set();
    printf("All tests passed.\n");
    return 0;
}

