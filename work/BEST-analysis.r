make.path <- function(base, sut, type, time) {
  return(paste0(base, sut, "-", type, "-", time, "h-afhv-0"))
}

read.mono <- function (path, fuzzer, rounds=5) {
  vec <- c()
  for (i in 1:rounds) {
    p <- paste(path, i, "/", fuzzer, ".coverage.log", sep="")
    if (fuzzer == "union") {
      v <- read.csv(p, sep=" ")[360, 2]
    } else {
      v <- max(read.csv(p, sep=" ")[2])
    }
    vec <- append(vec, v)
  }
  return(vec)
}

read.coop <- function (path, rounds=5) {
  vec <- c()
  for (i in 1:rounds) {
    p <- paste(path, i, "/coverage.log", sep="")
    vec <- append(vec, max(read.csv(p, sep=" ")$global))
  }
  return(vec)
}

pairwise.do <- function (df, f) {
  for (i in 1:(length(df)-1)) {
    xi <- df[i]
    for (j in (i+1):length(df)) {
      xj <- df[j]
      f(xi, xj)
    }
  }
}

print.vs <- function (x, y) {
  cat("\n", names(x)[1], "vs", names(y)[1], "\n")
}

pairwise.best <- function (df, all=F) {
  pairwise.do(df, function (x, y) {
    print.vs(x, y)
    best.out <- BESTmcmc(as.vector(unlist(x)), as.vector(unlist(y)))
    if (all) { plotAll(best.out) }
    else { plot(best.out) }
    readline("enter to continue...")
  })
}

pairwise.t.test <- function (df) {
  pairwise.do(df, function (x, y) {
    print.vs(x, y)
    print(t.test(x, y))
  })
}

path.3tb <- "/media/SB-3TB/stored_work/"

path.djpeg.mono <- make.path(path.3tb, "djpeg", "mono", 24)
djpeg.aflfast <- read.mono(path.djpeg.mono, "aflfast")
djpeg.fairfuzz <- read.mono(path.djpeg.mono, "fairfuzz")
djpeg.honggfuzz <- read.mono(path.djpeg.mono, "honggfuzz")
djpeg.union <- read.mono(path.djpeg.mono, "union")
djpeg.single <- read.coop(make.path(path.3tb, "djpeg", "Htn", 6))
djpeg.multi <- read.coop(make.path(path.3tb, "djpeg", "Ht0", 6))

djpeg.monos <- data.frame(aflfast=djpeg.aflfast, fairfuzz=djpeg.fairfuzz,
                          honggfuzz=djpeg.honggfuzz)
djpeg.coop <- data.frame(single=djpeg.single, multi=djpeg.multi, union=djpeg.union)

path.objdump.mono <- make.path(path.3tb, "objdump", "mono", 24)
objdump.aflfast <- read.mono(path.objdump.mono, "aflfast")
objdump.fairfuzz <- read.mono(path.objdump.mono, "fairfuzz")
objdump.honggfuzz <- read.mono(path.objdump.mono, "honggfuzz")
objdump.union <- read.mono(path.objdump.mono, "union")
objdump.single <- read.coop(make.path(path.3tb, "objdump", "Htn", 6))
objdump.multi <- read.coop(make.path(path.3tb, "objdump", "Ht0", 6))

objdump.monos <- data.frame(aflfast=objdump.aflfast, fairfuzz=objdump.fairfuzz,
                            honggfuzz=objdump.honggfuzz)
objdump.coop <- data.frame(single=objdump.single, multi=objdump.multi, union=objdump.union)


