# FIPS IPC

# Introduction
This is the source code repository for the paper: Rethinking IPS Architecture: Overcoming the Logging Bottleneck. 
The following, will provide an overview over the contents of the repository and the measurement setup.
More detailed information on background, design, implementation and measurements can be found in the paper.

# Directories
- `external/` External libraries used for building
- `src/` Source files for implementation, scripts and configuration
- `results/` all measured data points under data in git lfs with all scripts to generate plots
- `third_party/bind` the bind version with FIPS IPC integration
- `measurements-scripts` contain scripts to orchistrate the measurements across
  multiple nodes

# External Dependencies
These libraries are required to be installed on the system, in order for cmake to build
successfully. 
- [liburing](https://github.com/axboe/liburing) version (0.7-3)
- [hyperscan](https://github.com/intel/hyperscan) version (5.4.0-2) (and its [dependencies](https://intel.github.io/hyperscan/dev-reference/getting_started.html#)) 
- google protobuf and grpc


# Build
The project can then be built using `./build.sh`, once all external dependencies are satisfied. The binaries will be located in `build/`

# Traffic Generator Setup
To generate traffic, the traffic generator [TRex](https://trex-tgn.cisco.com/) needs to be installed on machine 2. An installation guide can be found [here](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_download_and_installation). 

Once TRex has been successfully installed, the server can be started with:

`./t-rex 64 -i -c <number of cores>`

The console can be started with:

`./trex-console`

In the console, traffic can be started, using the scripts in `src/scripts/traffic_gen/` with the command:

`start -f <path to script>.py -d <duration (seconds)> -t --ppsi <invalid traffic (pps)> --ppsv <valid traffic (pps)>`

The traffic can be stopped by writing `stop` to the console, or killing the TRex server process.

The scripts used in the experiments are:
- `udp_testsvr_traffic_v4.py` IPv4 traffic only, 65534 clients sending invalid traffic
- `udp_testsvr_traffic_v6.py` IPv4 traffic only, 65534 clients sending invalid traffic
- `udp_testsvr_traffic_v4_v6.py` IPv4 & IPv6 traffic, 131068 clients sending invalid traffic

The number of clients can be adapted via changing the `IP_RANGE` constants at the top of the script. 
Source and destination IP addresses also may have to be adapted to the test environment.

# Measurement
The measurement during our experiments was conducted with the program `ebpf_cmdline` in `src/ebpf-helpers`. 

To start a measurement call:
`./ebpf_cmdline --stats --write`
The measurement can be terminated with `control+c` and the results will be written to a .csv file within the current directory.
