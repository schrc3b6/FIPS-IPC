all: xdp_ddos01_blacklist_user_cmdline xdp_ddos01_blacklist_savestats 

xdp_ddos01_blacklist_user_cmdline: xdp_ddos01_blacklist_cmdline.c
	gcc -Wall -g -I../../libbpf/src -g -L../../src/libbpf/libbpf/ xdp_ddos01_blacklist_cmdline.c -l:libbpf.a -lelf -lz -o xdp_ddos01_blacklist_user_cmdline


xdp_ddos01_blacklist_user_subet_cmdline: xdp_ddos01_blacklist_subnet_cmdline.c
	gcc -Wall -g -I../../libbpf/src -g -L../../src/libbpf/libbpf/ xdp_ddos01_blacklist_subnet_cmdline.c -l:libbpf.a -lelf -lz -o xdp_ddos01_blacklist_user_subnet_cmdline


xdp_ddos01_blacklist_savestats: xdp_ddos01_blacklist_savestats.c
	gcc -Wall -g -I../../libbpf/src -g -L../../src/libbpf/libbpf/ xdp_ddos01_blacklist_savestats.c -l:libbpf.a -lelf -lz -o xdp_ddos01_blacklist_savestats

