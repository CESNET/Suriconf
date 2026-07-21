#!/bin/bash

# Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
# Copyright: (C) 2026 CESNET, z.s.p.o.
# SPDX-License-Identifier: BSD-3-Clause

# This file tests generated Suricata configuration files and NIC settings.

set -e

tests=("bt_test1" "bt_test2" "bt_test3" "bt_test4" "bt_test5")
types=("_1Gbps" "_5Gbps" "_10Gbps" "_15Gbps" "_20Gbps")

sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq &&\
    sudo chmod +x /usr/local/bin/yq

for test in "${tests[@]}"; do
  for type in "${types[@]}"; do

    dir="${test}${type}"
    cd "$dir"
      for f in *yaml; do
      sudo rmmod irdma
      sudo rmmod ice && sudo modprobe ice
      sudo modprobe irdma
      sudo ip link set ens4f0 up
      sudo ip link set ens4f0 mtu 9000
      ts=$(echo "$f" | sed -E 's/.*-([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9:]{8})\.yaml/\1/')

       nic_script="nic_setup-${ts}.sh"

        if [[ -f "$nic_script" ]]; then
         echo "Running $nic_script"
         sudo bash "$nic_script"
       else
         echo "NIC script not found: $nic_script"
         exit 1
       fi

      sudo rm -f /var/log/suricata/suricata.log
      sudo rm -f /var/log/suricata/stats.log
      yq -i '(.outputs[] | select(has("stats")) | .stats.enabled) = "yes"' "${f}"
      ssh -f trex2 "cd /opt/trex/v3.06/ && nohup sudo ./t-rex-64 --cfg /etc/trex_cfg.yaml -f ./upf_dns_top50/${test}${type}.yaml -c 9 -d 360 > /dev/null 2>&1"
      sudo /usr/local/bin/suricata -c "$f" -k none -vvvv -l /var/log/suricata/ --af-packet=ens4f0 -S /usr/local/var/lib/suricata/rules/suricata.rules &
      sleep 380
      sudo pkill -SIGTERM Suricata-Main
      sleep 10
      sudo mv /var/log/suricata/suricata.log "./suricata_${f}.log"
      sudo mv /var/log/suricata/stats.log "./stats_${f}.log"
      #sudo ethtool -S ens4f0 | grep rx_dropped > "./nic_${f}.txt"
    done
    cd ..
  done
done

grep drops bt_test*/suricata_suricata* | awk -F'[:/()]' '{print $1, $13}'  > result.txt