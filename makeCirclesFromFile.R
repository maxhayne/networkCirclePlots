# Importing libraries
source("includes/libs.R")

outlierFile <- NULL
fileType <- NULL
sortType <- NULL
fast <- NULL
mask <- NULL
dests <- NULL
orientation <- NULL
banner <- NULL
subnet <- NULL
ncpCoreCount <- NULL

source("includes/cmdArgs.R")
source("networkCirclePlots.R")

# Calling circle plotting function
tic()
makeCirclesFromFile(outlierFile, name=name, fileType=fileType, sortType=sortType, fast=fast, mask=mask, dests=dests, orientation=orientation, banner=banner, subnet=subnet)
toc()