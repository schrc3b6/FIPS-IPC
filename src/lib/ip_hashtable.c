#include "ip_hashtable.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Helper function to compute hash
static uint16_t hash_ip(const void *key, int domain) {
    if (domain == AF_INET) {
        // struct in_addr *addr = (struct in_addr *)key;
        // return ntohl(addr->s_addr) & 0xFFFF;
        return (uint16_t) ((*(uint32_t *)key) >> 16);
    } else if (domain == AF_INET6) {
        // struct in6_addr *addr = (struct in6_addr *)key;
        // return ntohs(*((uint16_t *)addr->s6_addr)) & 0xFFFF;
        return *(__uint128_t *)key & 0xFFFF;
        // return *((uint16_t *)addr->s6_addr) & 0xFFFF;
    }
    return 0;
}

int ip_hashtable_init(struct ip_hashtable_t **htable, time_t search_time) {
    if (!htable) return IP_HTABLE_NULLPTR_ERR;

    struct ip_hashtable_t *new_table = (struct ip_hashtable_t *)malloc(sizeof(struct ip_hashtable_t));
    if (!new_table) return IP_HTABLE_MEM_ERR;

    new_table->search_time = search_time;
    new_table->free_list = NULL;
    new_table->free_list_size = 0;

    if (pthread_mutex_init(&new_table->free_list_lock, NULL) != 0) {
        free(new_table);
        return IP_HTABLE_MUTEX_ERR;
    }

    for (int i = 0; i < NBINS; ++i) {
        new_table->hbins[i].entry = NULL;
        if (pthread_mutex_init(&new_table->hbins[i].lock, NULL) != 0) {
            free(new_table);
            return IP_HTABLE_MUTEX_ERR;
        }

        struct ip_hashtable_entry_t *entry = (struct ip_hashtable_entry_t *)malloc(sizeof(struct ip_hashtable_entry_t));
        if (!entry) {
            free(new_table);
            return IP_HTABLE_MEM_ERR;
        }

        entry->next = new_table->free_list;
        new_table->free_list = entry;
        new_table->free_list_size++;
    }

    *htable = new_table;
    return IP_HTABLE_SUCCESS;
}

int ip_hashtable_insert(struct ip_hashtable_t *htable, void *key, int domain, time_t access_time) {
    if (!htable || !key || (domain != AF_INET && domain != AF_INET6)) return IP_HTABLE_ARG_ERR;

    uint16_t bin_index = hash_ip(key, domain);
    struct ip_hashtable_bin_t *bin = &htable->hbins[bin_index];
    // printf("ip:%u:bin_index:%hu:\n",*(uint32_t*)key,bin_index);

    if (pthread_mutex_lock(&bin->lock) != 0) return IP_HTABLE_MUTEX_ERR;

    struct ip_hashtable_entry_t *entry = bin->entry;
    while (entry) {
        if ((domain == AF_INET && (memcmp(&entry->key.ipv4, key, sizeof(struct in_addr)) == 0)) ||
            (domain == AF_INET6 && (memcmp(&entry->key.ipv6, key, sizeof(struct in6_addr)) == 0))) {
            if (entry->last_access + htable->search_time < access_time) {
                entry->count = 1;
                entry->last_access = access_time;
            } else {
                // entry->last_access = access_time;
                entry->count++;
                // printf("out of date\n");
            }
            int count = entry->count;
            pthread_mutex_unlock(&bin->lock);
            return count;
        }
        entry = entry->next;
    }

    if (pthread_mutex_lock(&htable->free_list_lock) != 0) {
        pthread_mutex_unlock(&bin->lock);
        return IP_HTABLE_MUTEX_ERR;
    }

    if (htable->free_list_size == 0) {
        size_t hugepage_size = getpagesize();
        struct ip_hashtable_entry_t *new_entries = (struct ip_hashtable_entry_t *)mmap(NULL, hugepage_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_entries == MAP_FAILED) {
            pthread_mutex_unlock(&htable->free_list_lock);
            pthread_mutex_unlock(&bin->lock);
            return IP_HTABLE_MEM_ERR;
        }

        for (size_t i = 0; i < hugepage_size / sizeof(struct ip_hashtable_entry_t); ++i) {
            new_entries[i].next = htable->free_list;
            htable->free_list = &new_entries[i];
        }
        htable->free_list_size += hugepage_size / sizeof(struct ip_hashtable_entry_t);
    }

    struct ip_hashtable_entry_t *new_entry = htable->free_list;
    htable->free_list = new_entry->next;
    htable->free_list_size--;

    pthread_mutex_unlock(&htable->free_list_lock);

    if (domain == AF_INET) {
        new_entry->key.ipv4 = *(struct in_addr *)key;
    } else {
        new_entry->key.ipv6 = *(struct in6_addr *)key;
    }
    new_entry->domain = domain;
    new_entry->last_access = access_time;
    new_entry->count = 1;
    new_entry->next = bin->entry;
    bin->entry = new_entry;

    pthread_mutex_unlock(&bin->lock);
    return 1;
}

int ip_hashtable_remove(struct ip_hashtable_t *htable, void *key, int domain) {
    if (!htable || !key || (domain != AF_INET && domain != AF_INET6)) return IP_HTABLE_ARG_ERR;

    uint16_t bin_index = hash_ip(key, domain);
    struct ip_hashtable_bin_t *bin = &htable->hbins[bin_index];

    if (pthread_mutex_lock(&bin->lock) != 0) return IP_HTABLE_MUTEX_ERR;

    struct ip_hashtable_entry_t *entry = bin->entry;
    struct ip_hashtable_entry_t *prev = NULL;

    while (entry) {
        if ((domain == AF_INET && memcmp(&entry->key.ipv4, key, sizeof(struct in_addr)) == 0) ||
            (domain == AF_INET6 && memcmp(&entry->key.ipv6, key, sizeof(struct in6_addr)) == 0)) {
            if (prev) {
                prev->next = entry->next;
            } else {
                bin->entry = entry->next;
            }

            int count = entry->count;

            if (pthread_mutex_lock(&htable->free_list_lock) != 0) {
                pthread_mutex_unlock(&bin->lock);
                return IP_HTABLE_MUTEX_ERR;
            }

            entry->next = htable->free_list;
            htable->free_list = entry;
            htable->free_list_size++;

            pthread_mutex_unlock(&htable->free_list_lock);
            pthread_mutex_unlock(&bin->lock);

            return count;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&bin->lock);
    return IP_HTABLE_NOEXIST;
}

int ip_hashtable_set(struct ip_hashtable_t *htable, void *key, int domain, uint32_t value, time_t access_time) {
    if (!htable || !key || (domain != AF_INET && domain != AF_INET6)) return IP_HTABLE_ARG_ERR;

    uint16_t bin_index = hash_ip(key, domain);
    struct ip_hashtable_bin_t *bin = &htable->hbins[bin_index];

    if (pthread_mutex_lock(&bin->lock) != 0) return IP_HTABLE_MUTEX_ERR;

    struct ip_hashtable_entry_t *entry = bin->entry;
    while (entry) {
        if ((domain == AF_INET && memcmp(&entry->key.ipv4, key, sizeof(struct in_addr)) == 0) ||
            (domain == AF_INET6 && memcmp(&entry->key.ipv6, key, sizeof(struct in6_addr)) == 0)) {
            int old_count = entry->count;
            entry->count = value;
            entry->last_access = access_time;
            pthread_mutex_unlock(&bin->lock);
            return old_count;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&bin->lock);
    return IP_HTABLE_NOEXIST;
}

int ip_hashtable_destroy(struct ip_hashtable_t **htable) {
    if (!htable || !*htable) return IP_HTABLE_NULLPTR_ERR;

    struct ip_hashtable_t *table = *htable;

    for (int i = 0; i < NBINS; ++i) {
        pthread_mutex_destroy(&table->hbins[i].lock);
        struct ip_hashtable_entry_t *entry = table->hbins[i].entry;
        while (entry) {
            struct ip_hashtable_entry_t *tmp = entry;
            entry = entry->next;
            free(tmp);
        }
    }

    pthread_mutex_destroy(&table->free_list_lock);
    while (table->free_list) {
        struct ip_hashtable_entry_t *tmp = table->free_list;
        table->free_list = table->free_list->next;
        free(tmp);
    }

    free(table);
    *htable = NULL;
    return IP_HTABLE_SUCCESS;
}

