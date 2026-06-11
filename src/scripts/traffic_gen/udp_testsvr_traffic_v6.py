from trex_stl_lib.api import *
from scapy.layers.dns import * # import from layers. in default only ipv4/ipv6 are imported for speedup 
import argparse

# Parameters
VALID_PAYLOAD : str = 'A'
INVALID_PAYLOAD : str = 'B'
DEFAULT_VALID_PPS = 500000
DEFAULT_INVALID_PPS = 1000000
SRC_IP = "2001:db8:db8::2"
DEST_IP = "2001:db8:db8::1"
DEST_PORT = 8080
SRC_PORT = 47777
VALID_IP_RANGE = "10.3.11.1", "10.3.11.254" #"2001:db8:abcd::1","2001:db8:abcd::fe"
INVALID_IP_RANGE = "192.168.0.1", "192.168.255.254" #"2001:db9:abcd::1","2001:db9:abcd::fe"

class STLS1(object):

    def __init__ (self):
        pass

    def create_stream1 (self,pps):

        pkt =  Ether()/IPv6(src=SRC_IP,dst=DEST_IP)/UDP(sport=SRC_PORT, dport=DEST_PORT)/(VALID_PAYLOAD.encode("ascii"))
        vm = STLScVmRaw( [STLVmFlowVar ( "ip_src",  min_value=VALID_IP_RANGE[0],max_value=VALID_IP_RANGE[1], size=4, step=1,op="inc"),
                          #STLVmFlowVar ( "ip_src",  min_value="32.1.13.184",max_value="32.254.13.184", size=4, step=256*256,op="inc"),
                          STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IPv6.src",offset_fixup=8 ), # write ip to packet IP.sr
                          STLVmFixChecksumHw(l3_offset="IPv6",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],
                          cache_size = 254
        )
        return STLStream(packet = STLPktBuilder(pkt = pkt ,vm = vm),
                         random_seed = 0x1234,# can be removed. will give the same random value
                         mode = STLTXCont(pps = pps),
                         flow_stats = STLFlowStats(pg_id = 1))
    def create_stream2 (self,pps):
                # DNS
        pkt =  Ether()/IPv6(src=SRC_IP,dst=DEST_IP)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(INVALID_PAYLOAD.encode("ascii"))
        vm = STLScVmRaw( [STLVmFlowVar ( "ip_src",  min_value=INVALID_IP_RANGE[0],max_value=INVALID_IP_RANGE[1], size=4, step=1,op="inc"),
                          STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IPv6.src",offset_fixup=4 ), # write ip to packet IP.sr
                          STLVmFixChecksumHw(l3_offset="IPv6",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],
                          #cache_size = 65022
                                                 )
        return STLStream(packet = STLPktBuilder(pkt = pkt ,vm = vm),
                         random_seed = 0x1234,# can be removed. will give the same random value
                         mode = STLTXCont(pps = pps),
                         flow_stats = STLFlowStats(pg_id = 1))
    
    def get_streams (self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--ppsv',
                            type=int,
                            default=DEFAULT_VALID_PPS,
                            help="Packets per second for valid traffic")
        parser.add_argument('--ppsi',
                            type=int,
                            default=DEFAULT_INVALID_PPS,
                            help="Packets per second for invalid traffic")
        args = parser.parse_args(tunables)
# create 1 stream 
        return [ self.create_stream1(args.ppsv),self.create_stream2(args.ppsi)]
        #return [ self.create_stream1(),self.create_stream2(args.pps)]
    

def register():
    return STLS1()



