#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#include <spooky-c.h>

#define DATAFILE "ip_hashes.csv"
#define NBINS 600011
#define INSERTIONS 600011

uint32_t hitsv4[NBINS];
uint32_t hitsv6[NBINS];
uint32_t hitsjoint[NBINS];


static inline uint32_t spooky_hash(void * src, uint8_t len)
{
   return spooky_hash32(src, len, 0) % NBINS;
}

int main(void)
{
    uint32_t i, colv4 = 0, colv6 = 0, coljoint = 0, hashv4, hashv6;
    __uint128_t addr_buf;

    memset(hitsv4, 0, sizeof(hitsv4));
    memset(hitsv6, 0, sizeof(hitsv6));
    
    for(i = 0; i < INSERTIONS; i++)
    {
        if(getrandom(&addr_buf, 16, 0) != 16)
        {
            perror("getrandom failed");
            exit(EXIT_FAILURE);
        }

        hashv4 = spooky_hash(&addr_buf, 4);
        hashv6 = spooky_hash(&addr_buf, 16);

        if(hitsv4[hashv4]) {colv4++;}
        if(hitsv6[hashv6]) {colv6++;}

        if(i % 2 == 0) 
        {
            if(hitsjoint[hashv6]){coljoint++;}
            hitsjoint[hashv6]++;
        }
        else 
        {
            if(hitsjoint[hashv4]){coljoint++;}
            hitsjoint[hashv4]++;
        }

        hitsv4[hashv4]++;
        hitsv6[hashv6]++;

    }

    FILE * datafile = fopen(DATAFILE, "w");

    if(datafile == NULL)
    {
        perror("fopen failed");
    }

    else 
    {
        fprintf(datafile,"Index;IPv4_count;IPv6_count;Joint_count\n");

        for(i = 0; i < NBINS; i++)
        {
            fprintf(datafile,"%d;%d;%d;%d\n", i, hitsv4[i], hitsv6[i], hitsjoint[i]);
        }
    }

    printf("Number of bins: %d, Number of insertions: %d\nCollisions: IPv4 total: %d, %.2lf%%, IPv6 total: %d, %.2lf%%, Joint: %d, %.2lf%%\n",
           NBINS, INSERTIONS, colv4, (colv4 / (double)INSERTIONS)*100, colv6, (colv6 / (double)INSERTIONS)*100, coljoint, (coljoint /(double)INSERTIONS)*100);

}


