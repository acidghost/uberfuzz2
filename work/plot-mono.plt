sut=ARG1
hours=ARG2
outfile="mono-".sut.".png"

# N.B.: run it from stored_work
load "../plot-base.plt"

set xrange [0:hours]

plot sut."-mono-".hours."h-aflfast.dat" u ($1/60):2 lw 4 t "AFLFast", \
     sut."-mono-".hours."h-fairfuzz.dat" u ($1/60):2 lw 4 t "FairFuzz", \
     sut."-mono-".hours."h-honggfuzz.dat" u ($1/60):2 lw 4 t "Honggfuzz", \
     sut."-mono-".hours."h-vuzzer.dat" u ($1/60):2 lw 4 t "VUzzer"

