# Command line arguments
option_list = list(
  make_option(c("-o", "--outlier-file"), type="character", default=NULL, 
              help="outliers file name (should include full path)", metavar="filename"),
  make_option(c("-t", "--type"), type="character", default="png", 
              help="file type of output {png,jpg,pdf} [default= %default]", metavar="file_ext"),
  make_option(c("-s", "--sort"), type="character", default="ip", 
              help="sort type of output {ip,cluster,threat} [default= %default]", metavar="string"),
  make_option(c("-a", "--aspect-ratio"), type="character", default="l", 
              help="aspect ratio of output page {l=landscape,p=portrait} [default= %default]", metavar="character"),
  make_option(c("-f", "--fast"), type="logical", action="store_true", default=FALSE,
              help="enable plotting speedups [default= %default]", metavar="logical"),
  make_option(c("-m", "--mask"), type="character", default="/0", 
              help="masking to be done to IPs {/0,/8,/16,/24,/32} [default= %default]", metavar="string"),
  make_option(c("-n", "--name"), type="character", default=NULL, 
              help="name of the output file (includes path) and the title above the plots in the image (if no title is provided), file name defaults to the outlier's filename [default= %default]", metavar="string"),
  make_option(c("-d", "--dests"), type="logical", action="store_true", default=FALSE, 
              help="destination sectors of circleplots will be labeled if <10 destinations [default= %default]", metavar="logical"),
  make_option(c("-c", "--cores"), type="integer", default=NULL,
              help="number of cores to use while drawing plots. default behavior uses detectCores()-2", metavar="integer"),
  make_option(c("-b", "--banner"), type="character", default=NULL,
              help="the banner (title) of the page of plots. defaults to the name of the file", metavar="string"),
  make_option(c("-S", "--subnet"), type="character", default=NULL,
              help="the subnet of the network being monitored. defaults to null, but if null, checks for subnet in outlierFile name between '<time>_subnet_outliers.tsv'", metavar="string"),
  make_option(c("-M", "--max-data"), type="integer", default=NULL,
              help="maximum packet count for a link or sector, above which a red dot or line will be drawn outside the sector [default= %default]", metavar="integer")
)
opt_parser = OptionParser(option_list=option_list)
opt = parse_args(opt_parser)

# Logic for outlier file
if (is.null(opt$'outlier-file')) {
  stop("An outlier file must be provided in the command line arguments. Use -h for help.")
} else {
  if(!file.exists(opt$'outlier-file')) {
    stop("The outlier file provided does not exist.")
  }
  outlierFile <<- opt$'outlier-file'
}

# Logic for file type
if (strcmpi("png",opt$type)) {
  fileType <<- "png"
} else if (strcmpi("jpg",opt$type) || strcmpi("jpeg",opt$type)) {
  fileType <<- "jpeg"
} else if (strcmpi("pdf",opt$type)) {
  fileType <<- "pdf"
} else {
  stop("The file type must be one of the three: 'png', 'pdf', 'jpg', or 'jpeg'.")
}

# Logic for sorting type
if (strcmpi(opt$sort,"ip")) {
  sortType <<- "ip"
} else if (strcmpi(opt$sort,"cluster")) {
  sortType <<- "cluster"
} else if (strcmpi(opt$sort,"threat")) {
  sortType <<- "threat"
} else {
  stop("The sort option must be one of the three: 'ip', 'cluster', or 'threat'.")
}

# Logic for aspect ratio
if (strcmpi(opt$'aspect-ratio',"l")) {
  orientation <<- "l"
} else if (strcmpi(opt$'aspect-ratio',"p")) {
  orientation <<- "p"
} else {
  stop("Aspect ratio must be either 'l' (landscape) or 'p' (portrait).")
}

# Logic for fast
if (opt$fast) {
  fast <<- TRUE
} else {
  fast <<- FALSE
}

# Logic for mask
if (strcmpi(opt$mask,"/0")) {
  mask <<- "/0"
} else if (strcmpi(opt$mask,"/8")) {
  mask <<- "/8"
} else if (strcmpi(opt$mask,"/16")) {
  mask <<- "/16"
} else if (strcmpi(opt$mask,"/24")) {
  mask <<- "/24"
} else if (strcmpi(opt$mask,"/32")) {
  mask <<- "/32"
} else {
  stop("Masking must be set to one of the four: '/0', '/8', '/16', '/24', or '/32'.")
}

# Logic for name
if (is.null(opt$name)) {
  name <<- NULL
} else {
  name <<- opt$n
}

# Logic for dests
if (opt$dests) {
  dests <<- TRUE
} else {
  dests <<- FALSE
}

# Logic for cores
if (is.null(opt$cores)) {
  ncpCoreCount <<- detectCores()-2
} else if (is.integer(opt$cores)){
  if (opt$cores > detectCores()) {
    ncpCoreCount <<- detectCores()
  } else if (opt$cores < 1){
    ncpCoreCount <<- 1
  } else {
    ncpCoreCount <<- opt$cores
  }
} else {
  stop("The number of cores must be an integer.")
}

# Logic for max data
if (is.null(opt$'max-data')) {
  maxData <<- NULL
} else if (is.integer(opt$'max-data')){
  maxData <<- opt$'max-data'
} else {
  stop("The maximum must be an integer value.")
}

# Logic for banner
if (is.null(opt$banner)) {
  banner <<- NULL
} else {
  banner <<- opt$banner
}

# Logic for subnet
if (is.null(opt$subnet)) {
  subnet <<- NULL
} else {
  subnet <<- opt$subnet
}