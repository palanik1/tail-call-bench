#!/bin/bash
set -e

nb_tc=$1
repeat=$2
overheads=()

clang -O2 -Wall -target bpf -I/usr/include/x86_64-linux-gnu -c -o mapwriter.o mapwriter.c
sudo sh -c 'rm /sys/fs/bpf/xdp_mapwriter  /sys/fs/bpf/xdp_mapreader /sys/fs/bpf/map_progs 2>/dev/null' || true
sleep 0.1
sudo bpftool prog loadall mapwriter.o /sys/fs/bpf/
map_id=$(sudo bpftool map show -j | jq '.[] | select( .type == "prog_array" and .owner_prog_type == "xdp" ) | .id')
echo "MAP ID: " $map_id 
sudo bpftool map pin id $map_id /sys/fs/bpf/map_progs

sudo bpftool map update pinned /sys/fs/bpf/map_progs key 0 0 0 0 value pinned "/sys/fs/bpf/xdp_mapreader"

sudo bpftool prog run pinned /sys/fs/bpf/xdp_mapwriter data_in data.bin repeat ${repeat} data_out a.out

#overheads+=( $(sudo bpftool prog run pinned /sys/fs/bpf/action_prog0 data_in data.bin repeat $repeat | grep -oP "(?<=: )\d+(?=ns)") )



echo -n "[ "
for k in ${overheads[@]}; do
	echo -n "$k, "
done
echo "]"
