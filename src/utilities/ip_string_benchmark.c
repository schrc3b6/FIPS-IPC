#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <stdlib.h>

#include <ip_to_str.h>

#define ITERATIONS 10000000

#define TIME_DIFF(timer1, timer2) \
(( timer2.tv_sec * 1.0E+9 + timer2.tv_nsec ) - \
( timer1.tv_sec * 1.0E+9 + timer1.tv_nsec )) / 1.0E+9

int main(void)
{
    uint32_t ipv4addr, indexv4, i;
    __uint128_t ipv6addr = 0, indexv6;
    struct timespec t1, t2;
    char ip_buf[INET6_ADDRSTRLEN];

    if(getrandom(&ipv6addr, 16, 0) != 16)
    {
        perror("getrandom failed");
        exit(EXIT_FAILURE);
    }

    ipv4addr = (u_int32_t )ipv6addr;
    indexv4 = ipv4addr;

    printf("Iterations: %d\n", ITERATIONS);

    clock_gettime(CLOCK_MONOTONIC,&t1);
    for(i = 0; i < ITERATIONS; i++)
    {
        inet_ntop(AF_INET, &indexv4, ip_buf, INET6_ADDRSTRLEN);
        indexv4++;
    }
    clock_gettime(CLOCK_MONOTONIC,&t2);
    printf("Execution time inet_ntop ipv4: %lfs\n", TIME_DIFF(t1,t2));

    indexv4 = ipv4addr;

    clock_gettime(CLOCK_MONOTONIC,&t1);
    for(i = 0; i < ITERATIONS; i++)
    {
        ipv4_to_str(&indexv4, ip_buf);
        indexv4++;
    }
    clock_gettime(CLOCK_MONOTONIC,&t2);
    printf("Execution time ip_to_str ipv4: %lfs\n", TIME_DIFF(t1,t2));

    indexv6 = ipv6addr;

    clock_gettime(CLOCK_MONOTONIC,&t1);
    for(i = 0; i < ITERATIONS; i++)
    {
        inet_ntop(AF_INET6, &indexv6, ip_buf, INET6_ADDRSTRLEN);
        indexv6++;
    }
    clock_gettime(CLOCK_MONOTONIC,&t2);
    printf("Execution time inet_ntop ipv6: %lfs\n", TIME_DIFF(t1,t2));

    indexv6 = ipv6addr;

    clock_gettime(CLOCK_MONOTONIC,&t1);
    for(i = 0; i < ITERATIONS; i++)
    {
        ipv6_to_str(&indexv6, ip_buf);
        indexv6++;
    }
    clock_gettime(CLOCK_MONOTONIC,&t2);
    printf("Execution time ip_to_str ipv6: %lfs\n", TIME_DIFF(t1,t2));


}