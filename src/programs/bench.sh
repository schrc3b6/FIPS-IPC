#!/usr/bin/bash
threads=(8 16)
repeat_count=10
for thread in "${threads[@]}"
do
for i in {10..24}
do
for ((j=1; j<=repeat_count; j++))
do
./bench-shm-ringbug -m writer -o 10000000 -s a -n 5 -l 60 -t $thread -w 2 -e $i >> result.csv & \
./bench-shm-ringbug -m reader -o 10000000 -s a -n 5 -l 60 -t $thread -w 2 -e $i >> result_reader.csv
sleep 1
./bench-fips-buf -m writer -o 10000000 -s a -n 5 -l 60 -t $thread -w 2 -e $i >> result.csv & \
./bench-fips-buf -m reader -o 10000000 -s a -n 5 -l 60 -t $thread -w 2 -e $i >> result_reader.csv
sleep 1
done
done
done
