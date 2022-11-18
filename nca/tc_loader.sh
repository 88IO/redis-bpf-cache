ifname=$1
## init
# tc qdisc add dev $ifname clsact
## unload 
tc filter del dev $ifname egress
## load
tc filter add dev $ifname egress bpf da object-pinned /sys/fs/bpf/enp1s0f1/tc_tx_filter
