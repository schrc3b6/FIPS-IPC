#!/usr/bin/bash

# Adds the address range IP_PREFIX.IP_START - IP_PREFIX_IP_END
# as secondary addresses to INTERFACE

IP_PREFIX="10.3.10"
IP_START=1
IP_END=130
INTERFACE="enp24s0f0np0"
SUBNET=24

for ((i=IP_START; i<=$IP_END;i++))
do
    ip addr del "$IP_PREFIX.$i/$SUBNET" dev $INTERFACE
done

