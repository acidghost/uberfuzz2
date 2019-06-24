$1 == "Hash:" {
    current_hash = $2
}

$1 == "Fuzzer:" {
    current_fuzzer = $2
}

$1 == "File:" {
    ("date -r "$2" '+%s'")|getline date_s
    date=strtonum(date_s)
    if (files[current_hash] == "" || date < dates[current_hash]) {
        dates[current_hash] = date
        fuzzers[current_hash] = current_fuzzer
        files[current_hash] = $2
    }
}

END {
    for (h in files) {
        f = files[h]
        d = dates[h]
        fz = fuzzers[h]
        print h, d - start_time, fz, f
    }
}

