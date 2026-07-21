#!/bin/bash

# Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
# Copyright: (C) 2026 CESNET, z.s.p.o.
# SPDX-License-Identifier: BSD-3-Clause

# This file generates Suricata configuration files and NIC settings.

set -e

tests=("bt_test1" "bt_test2" "bt_test3" "bt_test4" "bt_test5")
types=("_1Gbps" "_5Gbps" "_10Gbps" "_15Gbps" "_20Gbps")

for test in "${tests[@]}"; do
  for type in "${types[@]}"; do

    dir="${test}${type}"
    mkdir -p "$dir"

    for i in {0..9}; do
      echo "Running $dir iteration $i"
      sudo rmmod irdma
      sudo rmmod ice && sudo modprobe ice
      sudo modprobe irdma
      sudo ip link set ens4f0 up
      sudo ip link set ens4f0 mtu 9000
      ssh -f trex2 "cd /opt/trex/v3.06/ && nohup sudo ./t-rex-64 --cfg /etc/trex_cfg.yaml -f ./upf_dns_top50/${test}${type}.yaml -c 9 -d 360 > /dev/null 2>&1"
      cargo run -- -v  -o"-k none -vvvv -l /var/log/suricata/ -S /usr/local/var/lib/suricata/rules/suricata.rules"
    done
    sudo mv tmp/suricata_result* "$dir"
    sudo mv tmp/nic_setup* "$dir"

  done
done