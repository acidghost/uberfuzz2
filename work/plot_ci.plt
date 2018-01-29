filename=ARG1

datfile=filename.".dat"

set title system("basename ".datfile)

set key on outside left top horizontal center
plot datfile u 1:2 w lines lt rgb "blue" title "mean", \
     datfile u 1:3 w lines lt rgb "orange" title "low CI", \
     datfile u 1:4 w lines lt rgb "red" title "high CI"

# the following draws error bars
# set key off
# plot datfile u 1:2:3:4 w yerrorlines

set terminal png size 1024,768
set output filename.".png"
replot
