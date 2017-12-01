#!/usr/bin/env bash

function uber_beep {
  ((speaker-test -t sine -f 600) & pid=$! ; sleep 1s ; kill -9 $pid) > /dev/null
}

function uber_init_env {
  export VUZZER_ROOT=/home/acidghost/SB-uni/master/thesis/vuzzer-64bit
  export PIN_ROOT=/media/SB-1TB/workarea/uni/master/thesis/pin-2.13-62732-gcc.4.4.7-linux
  export RUST_LOG=DEBUG

	echo core | sudo tee /proc/sys/kernel/core_pattern
	echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
	echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
	echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
	sudo sysctl kernel.perf_event_mlock_kb=300000000
}

function uber_restore_env {
  unset VUZZER_ROOT
  unset PIN_ROOT
  unset RUST_LOG

	echo "|/usr/share/apport/apport %p %s %c %P" | sudo tee /proc/sys/kernel/core_pattern
	echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
	echo 0 | sudo tee /proc/sys/kernel/sched_child_runs_first
	echo 1 | sudo tee /proc/sys/kernel/randomize_va_space
	echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
	sudo sysctl kernel.perf_event_mlock_kb=30000
}

if [[ "$1" = "start" ]]; then
	uber_init_env
else
  uber_restore_env
fi
