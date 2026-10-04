#!/bin/bash
set -e
sudo systemctl stop irqbalance
sudo /usr/sbin/ethtool -K ens3f1np1 rx off
sudo /usr/sbin/ethtool -K ens3f1np1 tx off
sudo /usr/sbin/ethtool -K ens3f1np1 tso off
sudo /usr/sbin/ethtool -K ens3f1np1 gro off
sudo /usr/sbin/ethtool -K ens3f1np1 lro off
sudo /usr/sbin/ethtool -K ens3f1np1 tx off
sudo /usr/sbin/ethtool -K ens3f1np1 sg off
sudo /usr/sbin/ethtool -K ens3f1np1 txvlan off
sudo /usr/sbin/ethtool -K ens3f1np1 rxvlan off
sudo /usr/sbin/ethtool -l ens3f1np1
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.core.netdev_max_backlog=16384
sudo /usr/sbin/ethtool -i ens3f1np1
sudo /usr/sbin/ip link set ens3f1np1 down
sudo /usr/sbin/ethtool -X ens3f1np1 default
sudo /usr/sbin/ethtool -L ens3f1np1 combined 25
sudo /usr/sbin/ethtool -K ens3f1np1 rxhash on
sudo /usr/sbin/ip link set ens3f1np1 up
sudo /usr/sbin/ethtool -x ens3f1np1
sudo /usr/sbin/ethtool -X ens3f1np1 hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 25
sudo /usr/sbin/ethtool -A ens3f1np1 rx off tx off
sudo /usr/sbin/ethtool -C ens3f1np1 adaptive-rx off adaptive-tx off rx-usecs 125
sudo /usr/sbin/ethtool -g ens3f1np1
sudo /usr/sbin/ethtool -G ens3f1np1 rx 8192
sudo /usr/sbin/ethtool -X ens3f1np1 hfunc toeplitz
sudo /usr/sbin/ethtool -N ens3f1np1 rx-flow-hash tcp4 sdfn
sudo /usr/sbin/ethtool -N ens3f1np1 rx-flow-hash udp4 sdfn
sudo /usr/sbin/ethtool -N ens3f1np1 rx-flow-hash tcp6 sdfn
sudo /usr/sbin/ethtool -N ens3f1np1 rx-flow-hash udp6 sdfn
ls /sys/class/net/ens3f1np1/device/msi_irqs/
sudo sh -c 'echo 0 > /proc/irq/375/smp_affinity_list'
sudo sh -c 'echo 2 > /proc/irq/376/smp_affinity_list'
sudo sh -c 'echo 4 > /proc/irq/377/smp_affinity_list'
sudo sh -c 'echo 6 > /proc/irq/378/smp_affinity_list'
sudo sh -c 'echo 8 > /proc/irq/379/smp_affinity_list'
sudo sh -c 'echo 10 > /proc/irq/380/smp_affinity_list'
sudo sh -c 'echo 12 > /proc/irq/381/smp_affinity_list'
sudo sh -c 'echo 14 > /proc/irq/382/smp_affinity_list'
sudo sh -c 'echo 16 > /proc/irq/383/smp_affinity_list'
sudo sh -c 'echo 18 > /proc/irq/384/smp_affinity_list'
sudo sh -c 'echo 20 > /proc/irq/385/smp_affinity_list'
sudo sh -c 'echo 22 > /proc/irq/386/smp_affinity_list'
sudo sh -c 'echo 24 > /proc/irq/387/smp_affinity_list'
sudo sh -c 'echo 26 > /proc/irq/388/smp_affinity_list'
sudo sh -c 'echo 28 > /proc/irq/389/smp_affinity_list'
sudo sh -c 'echo 30 > /proc/irq/390/smp_affinity_list'
sudo sh -c 'echo 32 > /proc/irq/391/smp_affinity_list'
sudo sh -c 'echo 34 > /proc/irq/392/smp_affinity_list'
sudo sh -c 'echo 36 > /proc/irq/393/smp_affinity_list'
sudo sh -c 'echo 38 > /proc/irq/394/smp_affinity_list'
sudo sh -c 'echo 40 > /proc/irq/395/smp_affinity_list'
sudo sh -c 'echo 42 > /proc/irq/396/smp_affinity_list'
sudo sh -c 'echo 44 > /proc/irq/397/smp_affinity_list'
sudo sh -c 'echo 46 > /proc/irq/398/smp_affinity_list'
sudo sh -c 'echo 48 > /proc/irq/399/smp_affinity_list'
sudo sh -c 'for RX_QUEUE in /sys/class/net/ens3f1np1/queues/rx-*; do echo 0 > $RX_QUEUE/rps_cpus; done'
