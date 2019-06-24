make.path <- function(base, sut, type, time) {
  paste0(base, sut, "-", type, "-", time, "h-afhv-0")
}

read.mono <- function (path, fuzzer, idx=NULL, rounds=5) {
  vec <- c()
  for (i in 1:rounds) {
    p <- paste0(path, i, "/", fuzzer, ".coverage.log")
    data <- read.csv(p, sep=" ")
    idx.0 <- if (is.null(idx)) nrow(data) else idx
    vec <- append(vec, data[idx.0, 2])
  }
  vec
}

read.coop <- function (path, rounds=5) {
  vec <- c()
  for (i in 1:rounds) {
    p <- paste0(path, i, "/coverage.log")
    vec <- append(vec, max(read.csv(p, sep=" ")$global))
  }
  vec
}

pairwise.do <- function (df, f) {
  for (i in 1:(length(df)-1)) {
    xi <- df[i]
    for (j in (i+1):length(df)) {
      xj <- df[j]
      print.vs(xi, xj)
      f(xi, xj)
    }
  }
}

print.vs <- function (x, y) {
  cat("\n", names(x)[1], "vs", names(y)[1], "\n")
}

do.best <- function (x, y, ROPE=NULL, all=F, steps=1000000, burn=10000) {
  best.out <- BESTmcmc(as.vector(unlist(x)), as.vector(unlist(y)),
                       numSavedSteps=steps, burnInSteps=burn)
  ROPE.arg <- if (is.null(ROPE)) NULL else c(-ROPE, ROPE)
  if (all) {
    plotAll(best.out, ROPEm=ROPE.arg)
  } else {
    plot(best.out, ROPE=ROPE.arg)
  }
  best.out
}

pairwise.best <- function (df, ROPE=NULL, all=F) {
  pairwise.do(df, function (x, y) {
    do.best(x, y, ROPE, all)
    readline("enter to continue...")
  })
}

pairwise.t.test <- function (df) {
  pairwise.do(df, function (x, y) {
    print(t.test(x, y))
  })
}

compute.ROPE <- function (...) {
  mean(apply(data.frame(...), 2, sd))
}

save.pdf <- function (filename, width=4, height=4) {
  fname <- paste0(path.figures, filename, ".pdf")
  pdf(fname, width=width, height=height, pointsize=10)
  par(mgp=c(2.2,0.45,0), tcl=-0.4, mar=c(3.3,3.6,1.1,1.1))
}

compute.CI <- function (data, tex=F) {
  m <- mean(data)
  ci <- (qnorm(.975) * sd(data)) / sqrt(length(data))
  if (tex) {
    cat(m, "\\pm", ci)
  } else {
    c(m, ci)
  }
}

path.figures <- "~/SB-uni/master/thesis/writeup/figures/"
path.3tb <- "/media/SB-3TB/stored_work/"
path.thesis <- "~/SB-uni/master/thesis/uberfuzz2/work/stored_work/"

### Load djpeg data
path.djpeg.mono <- make.path(path.3tb, "djpeg", "mono", 24)
djpeg.aflfast <- read.mono(path.djpeg.mono, "aflfast")
djpeg.fairfuzz <- read.mono(path.djpeg.mono, "fairfuzz")
djpeg.honggfuzz <- read.mono(path.djpeg.mono, "honggfuzz")
djpeg.union <- read.mono(path.djpeg.mono, "union")
djpeg.union.6 <- read.mono(path.djpeg.mono, "union", idx=360)
djpeg.single <- read.coop(make.path(path.3tb, "djpeg", "Htn", 6))
djpeg.multi <- read.coop(make.path(path.3tb, "djpeg", "Ht0", 6))

djpeg.monos <- data.frame(aflfast=djpeg.aflfast, fairfuzz=djpeg.fairfuzz,
                          honggfuzz=djpeg.honggfuzz, union=djpeg.union)
djpeg.coop <- data.frame(single=djpeg.single, multi=djpeg.multi, union=djpeg.union.6)
djpeg.ROPE <- compute.ROPE(djpeg.aflfast, djpeg.fairfuzz, djpeg.honggfuzz)

### Load objdump data
path.objdump.mono <- make.path(path.3tb, "objdump", "mono", 24)
objdump.aflfast <- read.mono(path.objdump.mono, "aflfast")
objdump.fairfuzz <- read.mono(path.objdump.mono, "fairfuzz")
objdump.honggfuzz <- read.mono(path.objdump.mono, "honggfuzz")
objdump.union <- read.mono(path.objdump.mono, "union")
objdump.union.6 <- read.mono(path.objdump.mono, "union", idx=360)
objdump.single <- read.coop(make.path(path.3tb, "objdump", "Htn", 6))
objdump.multi <- read.coop(make.path(path.3tb, "objdump", "Ht0", 6))

objdump.monos <- data.frame(aflfast=objdump.aflfast, fairfuzz=objdump.fairfuzz,
                            honggfuzz=objdump.honggfuzz, union=objdump.union)
objdump.coop <- data.frame(single=objdump.single, multi=objdump.multi, union=objdump.union.6)
objdump.ROPE <- compute.ROPE(objdump.aflfast, objdump.fairfuzz, objdump.honggfuzz)

### Load tiff2pdf data
path.tiff2pdf.mono <- make.path(path.3tb, "tiff2pdf", "mono", 24)
tiff2pdf.aflfast <- read.mono(path.tiff2pdf.mono, "aflfast")
tiff2pdf.fairfuzz <- read.mono(path.tiff2pdf.mono, "fairfuzz")
tiff2pdf.honggfuzz <- read.mono(path.tiff2pdf.mono, "honggfuzz")
tiff2pdf.union <- read.mono(path.tiff2pdf.mono, "union")
tiff2pdf.union.6 <- read.mono(path.tiff2pdf.mono, "union", idx=360)
tiff2pdf.single <- read.coop(make.path(path.3tb, "tiff2pdf", "Htn", 6))
tiff2pdf.multi <- read.coop(make.path(path.3tb, "tiff2pdf", "Ht0", 6))

tiff2pdf.monos <- data.frame(aflfast=tiff2pdf.aflfast, fairfuzz=tiff2pdf.fairfuzz,
                            honggfuzz=tiff2pdf.honggfuzz, union=tiff2pdf.union)
tiff2pdf.coop <- data.frame(single=tiff2pdf.single, multi=tiff2pdf.multi, union=tiff2pdf.union.6)
tiff2pdf.ROPE <- compute.ROPE(tiff2pdf.aflfast, tiff2pdf.fairfuzz, tiff2pdf.honggfuzz)

### Load ming data
path.ming.mono <- make.path(path.thesis, "ming", "mono", 6)
ming.aflfast <- read.mono(path.ming.mono, "aflfast")
ming.fairfuzz <- read.mono(path.ming.mono, "fairfuzz")
ming.honggfuzz <- read.mono(path.ming.mono, "honggfuzz")
ming.union <- read.mono(path.ming.mono, "union")
ming.single <- read.coop(make.path(path.thesis, "ming", "Htn", 6))
ming.multi <- read.coop(make.path(path.thesis, "ming", "Ht0", 6))

ming.monos <- data.frame(aflfast=ming.aflfast, fairfuzz=ming.fairfuzz,
                         honggfuzz=ming.honggfuzz, union=ming.union)
ming.coop <- data.frame(single=ming.single, multi=ming.multi, union=ming.union)
ming.ROPE <- compute.ROPE(ming.aflfast, ming.fairfuzz, ming.honggfuzz)

