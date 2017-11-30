#!/usr/bin/env bash

oldcore="|/usr/share/apport/apport %p %s %c %P"
oldscaling="powersave"
oldsched=0

cwd=`pwd`

if [ "$1" = "start" ]; then
	echo core | sudo tee /proc/sys/kernel/core_pattern
	cd /sys/devices/system/cpu; echo performance | sudo tee cpu*/cpufreq/scaling_governor
	echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
	echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
	sudo sysctl kernel.perf_event_mlock_kb=300000000
else
	echo $oldcore | sudo tee /proc/sys/kernel/core_pattern
	cd /sys/devices/system/cpu; echo $oldscaling | sudo tee cpu*/cpufreq/scaling_governor
	echo $oldsched | sudo tee /proc/sys/kernel/sched_child_runs_first
	echo 1 | sudo tee /proc/sys/kernel/randomize_va_space
	echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
	sudo sysctl kernel.perf_event_mlock_kb=30000
fi
cd $cwd
