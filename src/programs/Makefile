CC=gcc
INCLUDES=-I../lib/include 
CCFLAGS=-Wall -g -O3
LDFLAGS=-lpthread -lconfig
#-fsanitize=thread
#-DDEBUG 

all: bench-fips-buf bench-shm-ringbug fips_counter-busy fips_counter-sleep fips_counter-yield fips_counter-yield-prio fips_counter-sleep-prio fips_producer

bench-fips-buf: benchmark.c benchmark_fips_buf.c ../lib/fips_buf.c
	${CC} ${INCLUDES} ${CCFLAGS} -o $@ $^ ${LDFLAGS}

bench-shm-ringbug: benchmark.c benchmark_shm_buf.c ../lib/shm_ringbuf.c
	${CC} ${INCLUDES} ${CCFLAGS} -o $@ $^ ${LDFLAGS}

fips_producer: test_fips_buf_producer.c ../lib/fips_buf.c
	${CC} ${INCLUDES} ${CCFLAGS} -o $@ $^ ${LDFLAGS}

fips_counter-busy: test_fips_buf_counter.c ../lib/fips_buf.c
	${CC} ${INCLUDES} ${CCFLAGS} -o $@ $^ ${LDFLAGS}

fips_counter-sleep: test_fips_buf_counter.c ../lib/fips_buf.c
	${CC} ${INCLUDES} ${CCFLAGS} -DSLEEP -o $@ $^ ${LDFLAGS}

fips_counter-yield: test_fips_buf_counter.c ../lib/fips_buf.c
	${CC} ${INCLUDES} ${CCFLAGS} -DYIELD -o $@ $^ ${LDFLAGS}

fips_counter-yield-prio: test_fips_buf_counter.c ../lib/fips_buf.c
	${CC} ${INCLUDES} ${CCFLAGS} -DYIELD_PRIO -o $@ $^ ${LDFLAGS}

fips_counter-sleep-prio: test_fips_buf_counter.c ../lib/fips_buf.c
	${CC} ${INCLUDES} ${CCFLAGS} -DSLEEP_PRIO -o $@ $^ ${LDFLAGS}

clean:
	rm -f bench-fips-buf bench-shm-ringbug fips_counter-busy fips_counter-sleep fips_counter-yield fips_counter-yield-prio fips_counter-sleep-prio
