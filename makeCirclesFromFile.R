# Importing libraries
if (!suppressMessages(require("funr", character.only = TRUE))) {
  install.packages("funr", dependencies = TRUE)
  library("funr", character.only = TRUE)
}
currentDirectory <- dirname(sys.script())
source(paste0(currentDirectory,"/includes/libs.R"))

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
maxData <- NULL

source(paste0(currentDirectory,"/includes/cmdArgs.R"))
source(paste0(currentDirectory,"/networkCirclePlots.R"))

# Calling circle plotting function
tic()
makeCirclesFromFile(outlierFile, name=name, fileType=fileType, sortType=sortType, fast=fast, mask=mask, dests=dests, orientation=orientation, banner=banner, subnet=subnet, max=maxData)
toc()