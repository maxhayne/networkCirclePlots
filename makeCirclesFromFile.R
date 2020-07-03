# Importing libraries
#script.dir <- dirname(sys.frame(1)$ofile)
#currentPath <- paste0(script.dir,"/")
#source(paste0(currentPath,"includes/libs.R"))
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

# source(paste0(currentPath,"includes/cmdArgs.R"))
# source(paste0(currentPath,"networkCirclePlots.R"))
source("includes/cmdArgs.R")
source("networkCirclePlots.R")

# Calling circle plotting function
makeCirclesFromFile(outlierFile, name=name, fileType=fileType, sortType=sortType, fast=fast, mask=mask, dests=dests, orientation=orientation, banner=banner, subnet=subnet)