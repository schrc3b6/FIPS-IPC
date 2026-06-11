#include <benchmark/benchmark.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "ip_hashtable.h"
#include <random>

struct ip_hashtable_t *htable;

in_addr generateRandomIPv4() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib(0, 0xFFFFFFFF); // 32-bit unsigned integer

    in_addr addr;
    addr.s_addr = distrib(gen); // generate a random 32-bit address

    return addr;
}

// Function to generate a random IPv6 address in in6_addr format
in6_addr generateRandomIPv6() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> distrib(0, 255); // Each byte (octet) ranges from 0 to 255

    in6_addr addr;
    for (int i = 0; i < 16; ++i) {
        addr.s6_addr[i] = distrib(gen); // Generate random 16 bytes
    }

    return addr;
}

void* insert_ipv4(void* arg) {
    struct in_addr addr = generateRandomIPv4();
    time_t current_time = time(NULL);
    ip_hashtable_insert(htable, &addr, AF_INET, current_time);
    return NULL;
}

void* insert_ipv6(void* arg) {
    struct in6_addr addr = generateRandomIPv6();
    time_t current_time = time(NULL);
    ip_hashtable_insert(htable, &addr, AF_INET6, current_time);
    return NULL;
}

static void BM_MultithreadedInsert(benchmark::State& state) {
    pthread_t threads[2];
    for (auto _ : state) {
        pthread_create(&threads[0], NULL, insert_ipv4, NULL);
        pthread_create(&threads[1], NULL, insert_ipv6, NULL);
        pthread_join(threads[0], NULL);
        pthread_join(threads[1], NULL);
    }
}

void* remove_ipv4(void* arg) {
    struct in_addr addr;
    inet_pton(AF_INET, "192.168.0.1", &addr);
    ip_hashtable_remove(htable, &addr, AF_INET);
    return NULL;
}

void* remove_ipv6(void* arg) {
    struct in6_addr addr;
    inet_pton(AF_INET6, "2001:db8::1", &addr);
    ip_hashtable_remove(htable, &addr, AF_INET6);
    return NULL;
}

static void BM_MultithreadedRemove(benchmark::State& state) {
    pthread_t threads[2];
    for (auto _ : state) {
        pthread_create(&threads[0], NULL, remove_ipv4, NULL);
        pthread_create(&threads[1], NULL, remove_ipv6, NULL);
        pthread_join(threads[0], NULL);
        pthread_join(threads[1], NULL);
    }
}

int main(int argc, char** argv) {
    ip_hashtable_init(&htable, 60);

    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RegisterBenchmark("BM_MultithreadedInsert", BM_MultithreadedInsert);
    ::benchmark::RegisterBenchmark("BM_MultithreadedRemove", BM_MultithreadedRemove);
    ::benchmark::RunSpecifiedBenchmarks();

    ip_hashtable_destroy(&htable);
    return 0;
}

