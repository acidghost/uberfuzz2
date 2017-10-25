# lanch with gnuplot -p -c plot.plt filename nfuzzers
filename=ARG1
nfuzzers=ARG2

# index of the first fuzzer column
start=3
# index of the last fuzzer column
end=system("expr ".nfuzzers." + 2")
# get fuzzers from header
fuzzers=system("head -n1 ".filename." | cut -d' ' -f".start."-".end)

set title filename
plot for [i=1:nfuzzers] filename u "unit":word(fuzzers, i) t word(fuzzers, i) w lp
