sut=ARG1
outfile="vs-".sut.".png"

# N.B.: run it from stored_work
load "../plot-base.plt"

maxval=system("sort -rn -k2 ".sut."-Htn-6h-afhv.dat ".sut."-Ht0-6h-afhv.dat ". \
  sut."-union-6h-afhv.dat 2> /dev/null | head -n1 | cut -f2 -d' '")

set yrange [maxval - (maxval*.3):]

plot sut."-Htn-6h-afhv.dat" u ($1/60):2 lw 4 t "single", \
     sut."-Ht0-6h-afhv.dat" u ($1/60):2 lw 4 t "multi", \
     sut."-union-6h-afhv.dat" u ($1/60):2 lw 4 t "union"

