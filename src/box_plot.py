"""
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file generates box plots from file result.txt.
Code was partially generated with assistance from Google Gemini.
"""

import re
import matplotlib.pyplot as plt
from collections import defaultdict
from matplotlib.patches import Patch
import numpy as np

plt.style.use("seaborn-v0_8-whitegrid")

with open("result.txt", "r") as f:
    lines = [line.strip() for line in f]

data = defaultdict(lambda: defaultdict(list))

for line in lines:
    name, perc = line.split()

    m = re.match(r'(bt_test\d+)_(\d+)Gbps', name)
    if not m:
        continue

    test = m.group(1)
    speed = int(m.group(2))
    value = float(perc.strip('%'))

    if value > 10.0: # higher drop rate then 10 is nonsense, test error
        continue

    data[test][speed].append(value)

tests = sorted(data.keys())
speeds = sorted(
    {speed for test in data.values() for speed in test.keys()}
)

colors = ["#4C72B0","#DD8452","#55A868","#C44E52","#8172B3"]

fig, ax = plt.subplots(figsize=(15, 8))

width = 0.13
group_spacing = 1.2

positions_base = np.arange(len(speeds)) * group_spacing

for i, test in enumerate(tests):

    box_data = []
    positions = []

    for j, speed in enumerate(speeds):
        box_data.append(data[test][speed])
        positions.append(positions_base[j] + i * width)

    bp = ax.boxplot(
        box_data,
        positions=positions,
        widths=width,
        patch_artist=True,
        manage_ticks=False,
        showmeans=False,
        meanline=False,
        medianprops=dict(color="black", linewidth=2),
        whiskerprops=dict(linewidth=1.2),
        capprops=dict(linewidth=1.2),
        flierprops=dict(
            marker='o',
            markersize=5,
            alpha=0.35,
            markerfacecolor='black'
        )
    )

    for patch in bp['boxes']:
        patch.set_facecolor(colors[i])
        patch.set_alpha(0.8)

ax.set_xticks(
    positions_base + width * (len(tests) - 1) / 2
)

ax.set_xticklabels(
    [f"{s} Gbps" for s in speeds],
    fontsize=19
)

ax.set_ylabel("Drop rate (%)", fontsize=20)
ax.set_xlabel("Speed", fontsize=20)
ax.set_ylim(-0.5, 10)
ax.tick_params(axis='y', labelsize=19)

legend_handles = [Patch(facecolor=colors[i], label=tests[i], alpha=0.8) for i in range(len(tests))]

ax.legend(
    handles=legend_handles,
    title="traffic profiles",
    fontsize=18,
    title_fontsize=19,
    frameon=True
)

ax.grid(True, axis='y', linestyle='--', alpha=0.4)

ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()

plt.savefig("boxplot.pdf", bbox_inches="tight")
plt.show()