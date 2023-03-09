CC = clang
CFLAGS = -O2 -Wall -Wextra -Werror -Wno-missing-braces -g

all: mp_bouncer tc_test

clean:
	rm -f *.bpf.o *.skel.h vmlinux.h mp_bouncer tc_test

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

mp_client: client.bpf.c vmlinux.h mp_bouncer.bpf.h mp_common.h
	$(CC) $(CFLAGS) -target bpf -c client.bpf.c -o mp_client.bpf.o

mp_server: server.bpf.c vmlinux.h mp_bouncer.bpf.h mp_common.h
	$(CC) $(CFLAGS) -target bpf -c server.bpf.c -o mp_server.bpf.o

mp_mirror_udp: mirror_udp.bpf.c vmlinux.h mp_common.h
	$(CC) $(CFLAGS) -target bpf -c mirror_udp.bpf.c -o mp_mirror_udp.bpf.o

mp_mirror_tcp: mirror_tcp.bpf.c vmlinux.h mp_common.h
	$(CC) $(CFLAGS) -target bpf -c mirror_tcp.bpf.c -o mp_mirror_tcp.bpf.o

tc_test: tc_test.bpf.c vmlinux.h mp_common.h
	$(CC) $(CFLAGS) -target bpf -c tc_test.bpf.c -o tc_test.bpf.o

skeletons: mp_client mp_server mp_mirror_udp mp_mirror_tcp
	bpftool gen skeleton ./mp_client.bpf.o > ./client.skel.h
	bpftool gen skeleton ./mp_server.bpf.o > ./server.skel.h
	bpftool gen skeleton ./mp_mirror_udp.bpf.o > ./mirror_udp.skel.h
	bpftool gen skeleton ./mp_mirror_tcp.bpf.o > ./mirror_tcp.skel.h

mp_bouncer: mp_bouncer.c skeletons mp_common.h tc_test
	$(CC) $(CFLAGS) mp_bouncer.c -o mp_bouncer -lbpf

.PHONY: all clean

.DELETE_ON_ERROR:
.SECONDARY:
