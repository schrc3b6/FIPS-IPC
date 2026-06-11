# Implementation

This directory contains all source files for the implementation, as well as 
scripts and configuration files used in the evaluation of the implementation.

# Directories

- `ebpf-helpers` contains binaries, for interacting with the eBPF program and related maps used by `simplefail2ban`
They are adapted versions of the programs found in `src/cmdline_prog`, in the repository for the master thesis of Florian Mikolajczak.
- `fail2ban-config` contains the jail and filter for `udp_server`, which were used in the evaluation of fail2ban.
- `lib` contains libraries used in the implementation, including the shared memory ring buffer.
- `programs` contains source files for the applications `udp_server`, `simplefail2ban` and `simplelogstash`.
- `scripts` contains scripts for traffic generation with TRex and experimental setup for the DUT
- `utilities` contains the source file for the `poll_rbuf` utility, that can be used to inspect the shared memory ring buffer.
Additionally, two benchmarks for the hashfunction and binary IP to string conversion are included.

