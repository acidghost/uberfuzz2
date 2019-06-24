{
    if ($1 in times) {
        times[$1] = times[$1] SUBSEP $2
    } else {
        times[$1] = $2
    }
}

END {
    idx = 0
    for (h in times) {
        n = split(times[h], ts, SUBSEP)
        for (i = 1; i < n + 1; i++) {
            print idx, h, ts[i]
        }
        idx++
    }
}

