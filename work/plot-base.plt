set terminal png size 1280,720
set output outfile

set style data line

set xlabel "Time (hours)" font ",26" offset 0,-2,0
set ylabel "Coverage (BTS transitions)" font ",26" offset -1,0,0
set lmargin 10
set bmargin 6
set grid linetype 0 linewidth 2 linecolor rgb "#DCDCDC"
set key on outside left top horizontal center font ",30"
set ytics rotate by 45 right font ",20"
set xtics font ",26" offset 0,-1,0

