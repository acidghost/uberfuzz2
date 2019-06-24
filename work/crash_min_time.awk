{
    if (times[$1] == "" || $2 < times[$1]) {
        times[$1] = $2
        fuzzers[$1] = $3
        files[$1] = $4
    }
}

END {
    for (h in files) {
        t = times[h]
        fz = fuzzers[h]
        f = files[h]
        print h, t, fz, f
    }
}

