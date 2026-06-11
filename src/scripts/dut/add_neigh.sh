#!/bin/bash

# Finds the MAC Address of the target ip and adds
# the address range IP_PREFIX.IP_START - IP_PREFIX.IP_END
# to the arp table, mapping to the MAC of the target

TARGET_IPADDR="10.3.10.132"
TARGET_IP6ADDR="2001:db8:db8::2"
ping $TARGET_IPADDR -c 1 -q
ping6 $TARGET_IP6ADDR -c 1 -q
IP_PREFIX_VAL="10.3.11"
IP_PREFIX_INVAL="192.168"
IP6_PREFIX="2001:db8:db8"
INTERFACE=$(ip route | grep "$IP_PREFIX_VAL.*" | cut -d ' ' -f3)
INTERFACEV6=$(ip -6 route | grep "$IP6_PREFIX:*" | cut -d ' ' -f3)
ETHER_ADDR=$(ip neigh show | grep $TARGET_IPADDR | cut -d ' ' -f5)
ETHER_ADDRV6=$(ip -6 neigh show | grep $TARGET_IP6ADDR | cut -d ' ' -f5)
IP_VALID_START=1
IP_VALID_END=254
IP_INVALID_START=1
IP_INVALID_END=254
IP6_VALID_START=2817
IP6_VALID_END=3070
IP6_INVALID_START=1
IP6_INVALID_END=65535

# Valid ipv4
for ((i=IP_VALID_START;i<=IP_VALID_END;i++))
do
   ip neigh add "$IP_PREFIX_VAL.$i" lladdr $ETHER_ADDR dev $INTERFACE
done 

# Invalid ipv4

for((i=IP_INVALID_START-1;i<=IP_INVALID_END+1;i++))
do
   for ((j=IP_INVALID_START;j<=IP_INVALID_END;j++))
   do
      ip neigh add "$IP_PREFIX_INVAL.$j.$i" lladdr $ETHER_ADDR dev $INTERFACE
   done 
done

# Valid ipv6
for ((i=IP6_VALID_START;i<=IP6_VALID_END;i++))
do
   ip neigh add "2001:db8:db8:0:a03:$(printf '%x\n' $i):0:2" lladdr $ETHER_ADDRV6 dev $INTERFACEV6
done

## Invalid ipv6
for ((i=IP6_INVALID_START;i<=IP6_INVALID_END;i++))
do
   ip -6 neigh add "2001:db8:c0a8:$(printf '%x\n' $i)::2" lladdr $ETHER_ADDRV6 dev $INTERFACEV6
done
