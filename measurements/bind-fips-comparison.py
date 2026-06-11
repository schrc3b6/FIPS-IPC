from mnm import Command, Action, ActionKind, Measurements
import requests, json, datetime
import re
import logging
import uuid
from itertools import chain

URL = 'https://mattermost.cs.uni-potsdam.de/hooks/iit5zcgckjr67j3hbsityocjjc'

class FIPSResult:
    pps: int = 0
    packets: int = 0
    duration: int = 0
    lines: int = 0
    kind: str = ""
    uuid: str = ""
    lines_re: re.Pattern
    packet_re: re.Pattern
    address_range_index: int = 3

    def __init__(self, kind: str = "", packets: int =0, lines: int=0, pps: int=0, duration: int = 0, uuid: str = "", address_range_index=3, packet_re_str: str = r"(\d+) packets captured", lines_re_str: str = r"(\d+)"):
        self.kind = kind
        self.packets = packets
        self.lines = lines
        self.pps = pps
        self.uuid = uuid
        self.duration = duration
        self.packet_re = re.compile(packet_re_str)
        self.lines_re = re.compile(lines_re_str)
        self.address_range_index = address_range_index

    def __str__(self):
        return f"{self.kind};{self.duration};{self.pps};{self.packets};{self.uuid};{self.address_range_index}"

    def add_packets_result(self, packets_str: str):
        logging.info(f"Adding packets result: {packets_str}\n")
        packets_match = self.packet_re.search(packets_str)
        if packets_match:
            self.packets = int(packets_match.group(1))
        else:
            print(f"Failed to parse packets: {packets_str}")
        

    def add_lines_result(self, lines_str: str):
        logging.info(f"Adding lines result: {lines_str}\n")
        lines_match = self.lines_re.search(lines_str)
        if lines_match:
            self.lines = int(lines_match.group(1))
        else:
            print(f"Failed to parse lines: {lines_str}")

current_result = FIPSResult()

setup_default = [
    Command(Action(ActionKind.COMMAND, "cp /etc/systemd/system/named.service.d/override.conf_default /etc/systemd/system/named.service.d/override.conf"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl stop rsyslog"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl stop rsyslog.socket"), "fips3"),
    Command(Action(ActionKind.COMMAND, "ln -fs /run/systemd/journal/dev-log /dev/log"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl restart systemd-journald-dev-log.socket"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl restart systemd-journald"), "fips3"),
    Command(Action(ActionKind.COMMAND, "ln -fs /etc/default/named_default /etc/default/named"), "fips3"),
    Command(Action(ActionKind.COMMAND, "ln -fs /etc/bind/named.conf.options_default /etc/bind/named.conf.options"), "fips3"),
    Command(Action(ActionKind.COMMAND, "ln -fs /etc/bind/named.conf.logging_none /etc/bind/named.conf.logging"), "fips3"),
    Command(Action(ActionKind.COMMAND, "rm -rf /mnt/scratch/logs/*"), "fips3"),
    Command(Action(ActionKind.COMMAND, "rm -f /dev/shm/sem.fips_zero_copy_sem_open && ipcs -m  | grep bind| cut -f2 -d' '|xargs ipcrm shm"), "fips3"),
    Command(Action(ActionKind.COMMAND, "rm -f /dev/shm/sem.fips_zero_copy_sem_open && ipcs -m  | grep root| cut -f2 -d' '|xargs ipcrm shm"), "fips3"),
    Command(Action(ActionKind.COMMAND, "/home/maxschro/fips-ipc/src/ebpf-helpers/ebpf_loader -c ens6f0np0"), "fips3"),
    Command(Action(ActionKind.COMMAND, "killall -9 dnstap"), "fips3"),
    Command(Action(ActionKind.COMMAND, "killall -9 xdp_ddos01_blacklist_user_cmdline"), "fips3"),
    Command(Action(ActionKind.COMMAND, "killall --signal INT -r simplefail2ban*"), "fips3"),
    Command(Action(ActionKind.COMMAND, "killall -9 udp_server"), "fips3"),
    Command(Action(ActionKind.COMMAND, "killall -9 shm_reader_zero"), "fips3"),
    Command(Action(ActionKind.COMMAND, "killall -9 shm_reader_zero-bin-to-str"), "fips3"),
    Command(Action(ActionKind.COMMAND, "killall -9 tcpdump"), "fips2"),
]

setup_fips_syslog =  [
    Command(Action(ActionKind.COMMAND, "ln -fs /etc/default/named_fips /etc/default/named"), "fips3"),
    Command(Action(ActionKind.COMMAND, "ln -fs /etc/bind/named.conf.logging_syslog /etc/bind/named.conf.logging"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl restart named"), "fips3"),
]

setup_fips_bin =  [
    Command(Action(ActionKind.COMMAND, "cp /etc/systemd/system/named.service.d/override.conf_fips /etc/systemd/system/named.service.d/override.conf"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl restart named"), "fips3"),
]

setup_file =  [
    Command(Action(ActionKind.COMMAND, "ln -fs /etc/bind/named.conf.logging_file /etc/bind/named.conf.logging"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips3"),
    Command(Action(ActionKind.COMMAND, "systemctl restart named"), "fips3"),
]

pre_measure_fips_syslog = [
    Command(Action(ActionKind.OPEN_SHELL), "fips3", "3"),
    Command(Action(ActionKind.SEND_TO_SHELL, '/home/maxschro/fips-ipc/build/src/programs/sf2b/simplefail2ban_fips_buf_local --bantime=60 --findtime=100 --limit=10\n'), "fips3", "3"),
    Command(Action(ActionKind.SLEEP, "3.1"), "fips3", "3"),
    Command(Action(ActionKind.OPEN_SHELL), "fips3", "4"),
    Command(Action(ActionKind.SEND_TO_SHELL, '/home/maxschro/fips-ipc/build/src/cmdline_prog/ebpf_cmdline --stats > /mnt/scratch/logs/xdp.log\n'), "fips3", "4"),
]

pre_measure_fips_bin = [
    Command(Action(ActionKind.OPEN_SHELL), "fips3", "3"),
    Command(Action(ActionKind.SEND_TO_SHELL, '/home/maxschro/fips-ipc/build/src/programs/sf2b/simplefail2ban_fips_buf_binary_local --bantime=60 --findtime=100 --limit=10\n'), "fips3", "3"),
    Command(Action(ActionKind.SLEEP, "3.1"), "fips3", "3"),
    Command(Action(ActionKind.OPEN_SHELL), "fips3", "4"),
    Command(Action(ActionKind.SEND_TO_SHELL, '/home/maxschro/fips-ipc/build/src/cmdline_prog/ebpf_cmdline --stats > /mnt/scratch/logs/xdp.log\n'), "fips3", "4"),
]

pre_measure_file = [
    Command(Action(ActionKind.OPEN_SHELL), "fips3", "3"),
    Command(Action(ActionKind.SEND_TO_SHELL, '/home/maxschro/fips-ipc/build/src/programs/sf2b/simplefail2ban_posix_io_local --file=/mnt/scratch/logs/query.log --bantime=60 --findtime=100 --limit=10\n'), "fips3", "3"),
    Command(Action(ActionKind.SLEEP, "3.1"), "fips3", "3"),
    Command(Action(ActionKind.OPEN_SHELL), "fips3", "4"),
    Command(Action(ActionKind.SEND_TO_SHELL, '/home/maxschro/fips-ipc/build/src/cmdline_prog/ebpf_cmdline --stats > /mnt/scratch/logs/xdp.log\n'), "fips3", "4"),
]

post_measure_fips_syslog = [
    Command(Action(ActionKind.SEND_TO_SHELL, '\x03'), "fips3", "3"),
    Command(Action(ActionKind.SEND_TO_SHELL, '\x03'), "fips3", "4"),
    Command(Action(ActionKind.SLEEP, "1.1"), "fips3", "3"),
    Command(Action(ActionKind.READ_FROM_SHELL), "fips3", "3", post_hook=lambda self, result: (print(result.stdout), print(result.stderr))),
    Command(Action(ActionKind.READ_FROM_SHELL), "fips3", "4"),
    Command(Action(ActionKind.CLOSE_SHELL), "fips3", "3"),
    Command(Action(ActionKind.CLOSE_SHELL), "fips3", "4"),
]

post_measure_fips_bin = post_measure_fips_syslog
post_measure_file = post_measure_fips_syslog

start_measure = [
    Command(Action(ActionKind.OPEN_SHELL), "fips2", "1"),
    Command(Action(ActionKind.SLEEP, "1")),
    Command(Action(ActionKind.SEND_TO_SHELL, 'cd /home/maxschro/pcaps\n'), "fips2", "1"),
    Command(Action(ActionKind.SLEEP, "1")),
    Command(Action(ActionKind.SEND_TO_SHELL, command_template='tcpdump -B 65536 -ni enp24s0f0np0 -w $$$uuid_str.pcap\n'), "fips2", "1"),
    Command(Action(ActionKind.COMMAND, command_template="PYTHONPATH=/opt/trex/v3.06/automation/trex_control_plane/interactive /opt/trex/v3.06/venv/bin/python3 /home/maxschro/trex_scripts/trex-script.py --profile /home/maxschro/trex_scripts/ipv4_wanted_and_unwanted.py --duration $$$duration --pps_valid 42000 --pps_invalid $$$pps --address_range_index $$$address_range_index"), "fips4", environment={"PYTHONPATH": "/opt/trex/v3.06/automation/trex_control_plane/interactive"},post_hook=lambda self,result: print(self,result))# ,post_hook=lambda self,result: print(self,result)),
    #PYTHONPATH=/opt/trex/v3.06/automation/trex_control_plane/interactive /opt/trex/v3.06/venv/bin/python3 /home/maxschro/trex_scripts/trex-script.py --profile /home/maxschro/trex_scripts/ipv4_wanted_and_unwanted.py --duration 10 --pps_valid 42000 --pps_invalid 10 --address_range_index 3
 
]

stop_measure = [
    Command(Action(ActionKind.SLEEP, "0.5"), "fips2", "1"),
    Command(Action(ActionKind.READ_FROM_SHELL), "fips2", "1"),
    Command(Action(ActionKind.SEND_TO_SHELL, '\x03'), "fips2", "1"),
]

read_results = [
    Command(Action(ActionKind.COMMAND, command_template="mv /mnt/scratch/logs/xdp.log /home/maxschro/results/xdp/$$$uuid_str"), "fips3",post_hook=lambda self, result: print(result.stdout)),
    Command(Action(ActionKind.SLEEP, "1"), "fips2", "1"),
    Command(Action(ActionKind.READ_FROM_SHELL), "fips2", "1", post_hook=lambda self, result: current_result.add_packets_result(result.stdout)),
    Command(Action(ActionKind.CLOSE_SHELL), "fips2", "1"),
]

for command in setup_default:
    command.post_hook = lambda self, result: None

commands = {
    "file" : setup_default + setup_file + pre_measure_file + start_measure + stop_measure + post_measure_file + read_results,
    "fips_bin": setup_default + setup_fips_bin + pre_measure_fips_bin + start_measure + stop_measure + post_measure_fips_bin + read_results,
    # "fips_syslog": setup_default + setup_fips_syslog + pre_measure_fips_syslog + start_measure + stop_measure + post_measure_fips_syslog + read_results,
}

for k,v in commands.items():
    for command in v:
        if command.post_hook is None:
            command.post_hook = lambda self, result: print(result.stderr) if len(result.stderr) > 0 else None 


#--bantime=60 --findtime=10 --limit=100
duration = 360
# pps_values = list(range(1000000, 10000001, 1000000))
repetitions = 3
# pps_values = list([2000000,3000000,5000000])
pps_values = list([10000000])
# range_list = list(range(3, 12))
range_list = [3]
print(f"Running Measurements for following pps values: {pps_values}")
measurement_count = len(pps_values)*len(commands)*repetitions *len(range_list)
payload = {"text": f"measurement started at {datetime.datetime.now()} estimated runtime: {str(datetime.timedelta(seconds=measurement_count*(duration+5)))} seconds, using nodes: fips2 fips3 fips4, successful completion will be posted here"}
r = requests.post(URL, data=json.dumps(payload))
measurement_done = 0

timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M")
filename = f"results_{timestamp}.csv"
with open(filename, "w") as f:
    f.write("kind;duration;pps;packets;lines\n")

    for k,v in commands.items():
        print(f"Running Measurements for {k}")
        for range_value in range_list:
            for pps in pps_values:
                print(f"Running {k} for pps {pps}")
                for i in range(repetitions):
                    print(f"Running {k} iteration {i}")
                    m=Measurements(v, become_root=True)
                    uuid_str = str(uuid.uuid4().hex)
                    current_result = FIPSResult(k, pps=pps, duration=duration, uuid=uuid_str, address_range_index=range_value)
                    m.run({ "duration": str(duration), "pps": str(pps), "uuid_str": uuid_str, "address_range_index": str(range_value)})
                    f.write(str(current_result))
                    f.write("\n")
                    f.flush()
                    measurement_done += 1 
                    if measurement_done % 5 == 0:
                        payload = {"text": f"measurement {(measurement_done/measurement_count)*100} % done"}
                        r = requests.post(URL, data=json.dumps(payload))

payload = {"text": "measurement completed successful :)"}
r = requests.post(URL, data=json.dumps(payload))
