#!/usr/bin/env zsh

pid=$1

uptime=`cat /proc/uptime | cut -d' ' -f1`

stat=`cat /proc/${pid}/stat`
comm=`echo $stat | cut -d' ' -f2`
utime=`echo $stat | cut -d' ' -f14`
stime=`echo $stat | cut -d' ' -f15`
cutime=`echo $stat | cut -d' ' -f16`
cstime=`echo $stat | cut -d' ' -f17`
starttime=`echo $stat | cut -d' ' -f22`

echo "$pid $comm"
echo "User time: $utime ($cutime)"
echo "Kernel time: $stime ($cstime)"

Hz=`getconf CLK_TCK`

total_time=$[$utime + $stime]
total_time_c=$[$total_time + $cutime + $cstime]

seconds=$[$uptime - ($starttime / $Hz)]

cpu_usage=$[100 * (($total_time / $Hz) / $seconds)]
cpu_usage_c=$[100 * (($total_time_c / $Hz) / $seconds)]

echo "$cpu_usage % - $cpu_usage_c % in $[$seconds / 60] minutes"

