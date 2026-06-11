from mnm import Command, Action, ActionKind, Measurements
import requests, json, datetime
import re
import time
import logging
from itertools import chain
import uuid


URL = 'https://mattermost.cs.uni-potsdam.de/hooks/iit5zcgckjr67j3hbsityocjjc'

class FIPSResult:
    pps: int = 0
    packets: int = 0
    duration: int = 0
    lines: int = 0
    kind: str = ""
    lines_re: re.Pattern
    packet_re: re.Pattern

    #packet_re_str: str = r"(\d+) packets captured", lines_re_str: str = r"(\d+)"
    def __init__(self, kind: str = "", interval: int=0, duration: int = 0 ):
        self.kind = kind
        self.bytes = 0
        self.lines = 0
        self.rx_packets = 0
        self.tx_packets = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.interval = interval
        self.duration = duration
        self.filename = f"{uuid.uuid4()}.csv"

    def __str__(self):
        return f"{self.kind};{self.duration};{self.interval};{self.filename};{self.lines};{self.rx_packets};{self.tx_packets};{self.rx_bytes};{self.tx_bytes}"

    def add_metric_result(self, field_name: str, result_str: str, re_str:str = r"(\d+)"):
        # 1. Safety check: Does this field exist on the class?
        if not hasattr(self, field_name):
            logging.error(f"Cannot update '{field_name}': field does not exist on {self.__class__.__name__}")
            print(f"Error: Invalid field name '{field_name}'")
            return # Exit the function early
            
        logging.info(f"Adding {field_name} result: {result_str}\n")
        pattern = re.compile(re_str)
        match = pattern.search(result_str)
        
        if match:
            current_value = getattr(self, field_name, 0)
            parsed_value = int(match.group(1))
            
            if current_value == 0:
                setattr(self, field_name, parsed_value)
            else:
                setattr(self, field_name, parsed_value - current_value)
        else:
            print(f"Failed to parse {field_name}: {result_str}")

    def process_and_save_cvs(self,source:str, multiline_string:str):
        lines = multiline_string.splitlines()
        capturing = False
        extracted_lines = []
        
        for line in lines:
            if "ENDCSV" in line:
                capturing = False
                break  
                
            if capturing:
                extracted_lines.append(line)
                
            if "STARTCSV" in line:
                capturing = True
                
        cvs_content = "\n".join(extracted_lines)
        # cleaned_content = re.sub(r'\[.*?\]', '', cvs_content)
        
        
        # 4. Write the cleaned content to the file
        with open(f"{source}/{self.filename}", 'w', encoding='utf-8') as file:
            file.write(cvs_content)

current_result = FIPSResult()

setup_default = [
    Command(Action(ActionKind.COMMAND, "mkdir -p /mnt/scratch/logs"), "fips5"),
    Command(Action(ActionKind.COMMAND, "chmod 777 /mnt/scratch/logs/"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl stop rsyslog"), "fips5"),
    #Command(Action(ActionKind.COMMAND, "systemctl stop rsyslog.socket"), "fips5"),
    Command(Action(ActionKind.COMMAND, "rm -f /dev/log"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ln -fs /run/systemd/journal/dev-log /dev/log"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart systemd-journald-dev-log.socket"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart systemd-journald"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ln -fs /etc/nginx/nginx.conf.none /etc/nginx/nginx.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "rm -f /etc/systemd/system/nginx.service.d/override.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "rm -rf /mnt/scratch/logs/*"), "fips5"),
    Command(Action(ActionKind.COMMAND, "rm -f /dev/shm/sem.fips_zero_copy_sem_open && ipcs -m  | grep bind| cut -f2 -d' '|xargs ipcrm shm"), "fips5"),
    Command(Action(ActionKind.COMMAND, "rm -f /dev/shm/sem.fips_zero_copy_sem_open && ipcs -m  | grep root| cut -f2 -d' '|xargs ipcrm shm"), "fips5"),
    Command(Action(ActionKind.COMMAND, "killall python"), "p4-laptop"),
    Command(Action(ActionKind.COMMAND, "killall -9 shm_reader_zero"), "fips5"),
    Command(Action(ActionKind.COMMAND, "killall -9 shm_reader_zero-bin-to-str"), "fips5"),
    Command(Action(ActionKind.COMMAND, "killall -9 python"), "p4-laptop"),
    Command(Action(ActionKind.COMMAND, "killall -9 tcpdump"), "fips5"),
    Command(Action(ActionKind.COMMAND, "[ $(ip neigh | grep PERMANENT | wc -l) -lt 255 ] && source /home/maxschro/add-neigh-and-route-for-trex.sh"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ip addr add 10.4.0.2/16 dev enp13s0f0np0"), "fips5"),
    Command(Action(ActionKind.COMMAND, "'echo 16 > /sys/kernel/mm/hugepages/hugepages-524288kB/nr_hugepages'"), "bluefield"),
]

setup_none = [ 
    Command(Action(ActionKind.COMMAND, "cp /etc/systemd/system/nginx.service.d/override.conf.fips /etc/systemd/system/nginx.service.d/override.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ln -fs /opt/nginx/conf/nginx.conf.none /opt/nginx/conf/nginx.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart nginx"), "fips5"),
    Command(Action(ActionKind.SLEEP, "60")),
]

setup_fips_bin =  [
    Command(Action(ActionKind.COMMAND, "cp /etc/systemd/system/nginx.service.d/override.conf.fips /etc/systemd/system/nginx.service.d/override.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ln -fs /opt/nginx/conf/nginx.conf.fips /opt/nginx/conf/nginx.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart nginx"), "fips5"),
    Command(Action(ActionKind.SLEEP, "60")),
]

setup_file =  [
    Command(Action(ActionKind.COMMAND, "cp /etc/systemd/system/nginx.service.d/override.conf.fips /etc/systemd/system/nginx.service.d/override.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ln -fs /opt/nginx/conf/nginx.conf.file /opt/nginx/conf/nginx.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart nginx"), "fips5"),
    Command(Action(ActionKind.SLEEP, "60")),
]

setup_syslog =  [
    Command(Action(ActionKind.COMMAND, "cp /etc/systemd/system/nginx.service.d/override.conf.fips /etc/systemd/system/nginx.service.d/override.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ln -fs /opt/nginx/conf/nginx.conf.syslog /opt/nginx/conf/nginx.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "rm -f /dev/log"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart nginx"), "fips5"),
    # Command(Action(ActionKind.COMMAND, "systemctl restart rsyslog.socket"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart rsyslog"), "fips5"),
    Command(Action(ActionKind.SLEEP, "60")),
]

setup_journal_syslog =  [
    Command(Action(ActionKind.COMMAND, "cp /etc/systemd/system/nginx.service.d/override.conf.fips /etc/systemd/system/nginx.service.d/override.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "ln -fs /opt/nginx/conf/nginx.conf.syslog /opt/nginx/conf/nginx.conf"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl daemon-reload"), "fips5"),
    Command(Action(ActionKind.COMMAND, "systemctl restart nginx"), "fips5"),
    Command(Action(ActionKind.SLEEP, "60")),
]

pre_measure_fips_bin = [
    Command(Action(ActionKind.OPEN_SHELL), "fips5", "3"),
    Command(Action(ActionKind.SEND_TO_SHELL, '/root/fips-ipc/src/programs/fips_counter-sleep\n'), "fips5", "3"),
    #Command(Action(ActionKind.SEND_TO_SHELL, '/root/fips-ipc/build/src/programs/shm_reader_zero-bin-to-str -i 3 -p /mnt/scratch/logs/fips.txt -t 1\n'), "fips5", "3"),
]

post_measure_fips_bin = [
    Command(Action(ActionKind.SEND_TO_SHELL, '\x03'), "fips5", "3"),
    Command(Action(ActionKind.SLEEP, "0.1"), "fips5", "3"),
    Command(Action(ActionKind.READ_FROM_SHELL), "fips5", "3",post_hook=lambda self, result: current_result.add_metric_result("lines", result.stdout,re_str=r"read (\d+)")),
    Command(Action(ActionKind.CLOSE_SHELL), "fips5", "3"),
]

read_results_fips = [
    #Command(Action(ActionKind.COMMAND, "wc -l /mnt/scratch/logs/fips.txt"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("lines", result.stdout)),
]


read_results_file = [
    Command(Action(ActionKind.COMMAND, "wc -l /mnt/scratch/logs/access.log"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("lines", result.stdout)),
]

read_results_syslog = [
    Command(Action(ActionKind.COMMAND, "wc -l /mnt/scratch/logs/syslog.log"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("lines", result.stdout)),
]

read_results_journal = [
    Command(Action(ActionKind.COMMAND, "journalctl INVOCATION_ID=`systemctl show -p InvocationID --value nginx.service` + _SYSTEMD_INVOCATION_ID=`systemctl show -p InvocationID --value nginx.service` |wc -l"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("lines", result.stdout)),
]

start_measure = [
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep tx_packets_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("tx_packets", result.stdout, re_str=r"tx_packets_phy: (\d+)")),
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep rx_packets_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("rx_packets", result.stdout, re_str=r"rx_packets_phy: (\d+)")),
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep tx_bytes_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("tx_bytes", result.stdout, re_str=r"tx_bytes_phy: (\d+)")),
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep rx_bytes_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("rx_bytes", result.stdout, re_str=r"rx_bytes_phy: (\d+)")),
    Command(Action(ActionKind.OPEN_SHELL), "p4-laptop", "1"),
    Command(Action(ActionKind.OPEN_SHELL), "fips5", "4"),
    Command(Action(ActionKind.SLEEP, "1")),
    Command(Action(ActionKind.SEND_TO_SHELL, 'cd /home/maxschro/\n'), "fips5", "4"),
    Command(Action(ActionKind.SEND_TO_SHELL, command_template= 'tcpdump -B 65536 -ni enp13s0f0np0 -w date-$$$interval.pcap\n'), "fips5", "4"),
    Command(Action(ActionKind.SEND_TO_SHELL, 'cd /home/thomas/tofino-traffic-generator/tofino_traffic_generator/\n'), "p4-laptop", "1"),
    Command(Action(ActionKind.SEND_TO_SHELL, command_template='../.venv/bin/python main.py --time $$$duration -i $$$interval --source_cidr 10.4.0.3/16 -c\n'), "p4-laptop", "1"),
    Command(Action(ActionKind.SLEEP, "10")),
    Command(Action(ActionKind.READ_FROM_SHELL), "p4-laptop", "1", post_hook=lambda self,result: print(self,result)),
    Command(Action(ActionKind.OPEN_SHELL), "bluefield", "2"),
    Command(Action(ActionKind.SEND_TO_SHELL, 'cd /home/ubuntu/flow_counter/\n'), "bluefield", "2"),
    Command(Action(ActionKind.SEND_TO_SHELL, command_template='sudo ./build/doca_flow_monitor -- -l 70 -r pci/0000:03:00.0,pf0vf-1 -i 100000 -t $$$duration_counting -s\n'), "bluefield", "2"),
    Command(Action(ActionKind.SEND_TO_SHELL, '\n'), "p4-laptop", "1", post_hook=lambda self,result: print(self,result)),
    # Command(Action(ActionKind.COMMAND, command_template="python3 /mnt/scratch/max/trex_scripts/trex-script.py --profile /mnt/scratch/max/trex_scripts/ipv4_wanted_and_unwanted.py --duration $$$duration --pps_valid $$$pps"), "fips4", environment={"PYTHONPATH": "/mnt/scratch/Miko/trex-core/scripts/automation/trex_control_plane/interactive"}),# post_hook=lambda self,result: print(self,result)),
]

stop_measure = [
    Command(Action(ActionKind.SLEEP, command_template="$$$duration_counting"), "bluefield", "2"),
    Command(Action(ActionKind.SEND_TO_SHELL, '\x03'), "fips5", "4"),
    Command(Action(ActionKind.CLOSE_SHELL), "fips5", "4"),
]

read_results = [
    Command(Action(ActionKind.SLEEP, "1"), "p4-laptop", "1"),
    Command(Action(ActionKind.READ_FROM_SHELL), "p4-laptop", "1", post_hook=lambda self, result: current_result.process_and_save_cvs("switch", result.stdout)),
    Command(Action(ActionKind.CLOSE_SHELL), "p4-laptop", "1"),
    # Command(Action(ActionKind.READ_FROM_SHELL), "bluefield", "2"), #, post_hook=lambda self, result: print(result.stdout)),
    Command(Action(ActionKind.READ_FROM_SHELL), "bluefield", "2", post_hook=lambda self, result: current_result.process_and_save_cvs("bluefield",result.stdout)),
    Command(Action(ActionKind.CLOSE_SHELL), "bluefield", "2"),
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep tx_packets_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("tx_packets", result.stdout, re_str=r"tx_packets_phy: (\d+)")),
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep rx_packets_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("rx_packets", result.stdout, re_str=r"rx_packets_phy: (\d+)")),
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep tx_bytes_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("tx_bytes", result.stdout, re_str=r"tx_bytes_phy: (\d+)")),
    Command(Action(ActionKind.COMMAND, "ethtool -S enp13s0f0np0 | grep rx_bytes_phy:"), "fips5", post_hook=lambda self, result: current_result.add_metric_result("rx_bytes", result.stdout, re_str=r"rx_bytes_phy: (\d+)")),
]

commands = {
    #"fips_bin": setup_default + setup_fips_bin + pre_measure_fips_bin + start_measure + stop_measure + post_measure_fips_bin + read_results +read_results_fips,
    "none": setup_default + setup_none + start_measure + stop_measure + read_results,
    #"file" : setup_default + setup_file + start_measure + stop_measure + read_results + read_results_file,
    #"syslog" : setup_default + setup_syslog + start_measure + stop_measure + read_results + read_results_syslog,
    #"journal_syslog" : setup_default + setup_journal_syslog + start_measure + stop_measure + read_results + read_results_journal,
}

for k,v in commands.items():
    for command in v:
        if command.post_hook is None:
            command.post_hook = lambda self, result: print(result.stderr) if len(result.stderr) > 0 else None 

# million = 1000000
# ten_million = 10000000
# pps = million
duration = 60

# reset fips
# m=Measurements(setup_default)
# current_result = FIPSResult(k, pps=pps, duration=duration)
# m.run({ "duration": str(duration), "pps": str(pps) })


# run single iteration
# m=Measurements(commands["dnstap"])
# current_result = FIPSResult("dnstap", pps=pps, duration=duration)
# m.run({ "duration": str(duration), "pps": str(pps) })
# print(current_result)

#interval = [17] + list(chain(range(20, 50, 5),range(50, 100, 10), range(100, 1000, 100), range(1000, 10000, 500),range(10000, 31000, 5000))) 
interval = [100]
#interval = list(range(1000, 11000, 1000))
#interval = list(chain(range(100, 1000, 100), range(1000, 10000, 500),range(10000, 31000, 5000))) 
# pps_values = list([10000000])
print(f"Running Measurements for following interval values: {interval}")
measurement_count = len(interval)*len(commands)*3
# payload = {"text": f"measurement started at {datetime.datetime.now()} estimated runtime: {measurement_count*140} seconds, using nodes: fips2 fips5 fips4, successful completion will be posted here"}
payload = {"text": f"measurement started at {datetime.datetime.now()} estimated runtime: {str(datetime.timedelta(seconds=measurement_count*(duration+78)))} seconds, using nodes: fips5 and bluefield, successful completion will be posted here"}
r = requests.post(URL, data=json.dumps(payload))
measurement_done = 0

timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M")
filename = f"results_{timestamp}.csv"
with open(filename, "w") as f:
    f.write("kind;duration;interval;filename;lines;packets_rx;packets_tx;bytes_rx;bytes_tx\n")

    for i in range(3):
        print(f"iteration {i}")
        for interval_value in interval:
            print(f"Running iteration {i} for pps {interval_value}")
            for k,v in commands.items():
                while True:
                    print(f"Running Measurements for {k}")
                    m=Measurements(v, become_root=True)
                    current_result = FIPSResult(k, interval=interval_value, duration=duration)
                    try:
                        m.run({ "duration": str(duration), "interval": str(interval_value), "duration_counting": str(duration+5) })
                    except Exception as e:
                        print(f"Error during measurement for {k} with interval {interval_value}: {e}")
                        payload = {"text": f"Error during measurement for {k} with interval {interval_value}: {e}"}
                        r = requests.post(URL, data=json.dumps(payload))
                        time.sleep(60)
                        continue
                    break
                f.write(str(current_result))
                f.write("\n")
                f.flush()
                measurement_done += 1 
                if measurement_done % 10 == 0:
                    payload = {"text": f"measurement {(measurement_done/measurement_count)*100} % done"}
                    r = requests.post(URL, data=json.dumps(payload))

payload = {"text": "measurement completed successful :)"}
r = requests.post(URL, data=json.dumps(payload))
