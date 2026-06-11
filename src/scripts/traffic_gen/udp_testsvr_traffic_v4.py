import argparse
from trex_stl_lib.api import *

# Parameters
VALID_PAYLOAD : str = 'A'
INVALID_PAYLOAD : str = 'B'
DEFAULT_VALID_PPS = 10000
DEFAULT_INVALID_PPS = 1000000
SRC_IP = "10.3.10.132"
DEST_IP = "10.3.10.131"
DEST_PORT = 8080
SRC_PORT = 47777
VALID_IP_RANGE = "10.3.11.1","10.3.11.254"
INVALID_IP_RANGE = "192.168.0.1","192.168.255.254"

class STLS1(object):
    def __init__ (self):
        pass
    def create_stream1 (self,pps):
        pkt =  Ether()/IP(src=SRC_IP,dst=DEST_IP,id=1,tos=0)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(VALID_PAYLOAD.encode("ascii"))
        vm = STLScVmRaw([STLVmFlowVar("ip_src", min_value=VALID_IP_RANGE[0],max_value=VALID_IP_RANGE[1], size=4, step=1,op="inc"),
             STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),                
             STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],                      
             cache_size = 254

        )
        return STLStream(packet = STLPktBuilder(pkt = pkt ,vm = vm),
               mode = STLTXCont(pps = pps),
               flow_stats = STLFlowStats(pg_id = 1))
    def create_stream2 (self,pps):
        pkt2 = Ether()/IP(src=SRC_IP,dst=DEST_IP,id=1,tos=0)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(INVALID_PAYLOAD.encode("ascii"))
        vm2 = STLScVmRaw([STLVmFlowVar("ip_src",min_value=INVALID_IP_RANGE[0],max_value=INVALID_IP_RANGE[1], size=4, step=1,op="inc"),
              STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),
              STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],
              #cache_size = 65535
            )
        return STLStream(packet = STLPktBuilder(pkt = pkt2, vm =vm2),
               mode = STLTXCont(pps = pps),
               flow_stats = STLFlowStats(pg_id = 2))  
    def get_streams (self,tunables,**kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--ppsv',type=int,default=DEFAULT_VALID_PPS,
               help="Packets per second for valid traffic")
        parser.add_argument('--ppsi',type=int,default=DEFAULT_INVALID_PPS,
               help="Packets per second for invalid traffic")
        args = parser.parse_args(tunables)
        return [self.create_stream1(args.ppsv),self.create_stream2(args.ppsi)]
def register():
    return STLS1()

