#!/bin/sh

# Set our defaults
brif=bridge0
memsz=1024M
ncpu=`sysctl -n hw.ncpu`
netif=`netstat -4rn | grep -e '^default ' | awk '{print $NF}'`
tapif=tap0

netif_exists() {
    local netif=$1
    local iflist=`ifconfig -l`
    for I in $iflist; do
        if test $I == $netif; then
            return 0
        fi
    done
    return 1
}

if ! kldstat -qm vmm; then
    kldload vmm
fi

if ! netif_exists $tapif; then
    ifconfig $tapif create
    sysctl net.link.tap.up_on_open=1
fi

if ! netif_exists $brif; then
    ifconfig $brif create
    ifconfig $brif addm $netif addm $tapif
    ifconfig $brif up
fi

exec sh /usr/share/examples/bhyve/vmrun.sh -c $ncpu -m $memsz -t $tapif "$@"
