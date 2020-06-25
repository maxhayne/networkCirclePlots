currentPath <- paste0(getwd(),"/")
source(paste0(currentPath,"libs.R"))

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

source(paste0(currentPath,"cmdArgs.R"))
source(paste0(currentPath,"networkCirclePlots.R"))

# Calling circle plotting function
makeCircsFromFile(outlierFile, name=name, fileType=fileType, sortType=sortType, fast=fast, mask=mask, dests=dests, orientation=orientation, banner=banner, subnet=subnet)