if (!suppressMessages(require("pacman"))) install.packages("pacman")
pacman::p_load("pracma", "funr", "optparse", "parallel", "tictoc")
currentDirectory <- dirname(sys.script())

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
dataColumn <- NULL
hRatio <- NULL

source(paste0(currentDirectory,"/includes/cmdArgs.R"))
source(paste0(currentDirectory,"/includes/libs.R"))
source(paste0(currentDirectory,"/networkCirclePlots.R"))

# Calling circle plotting function
tic()
makeCirclesFromFile(outlierFile, name=name, fileType=fileType, sortType=sortType, fast=fast, mask=mask, dests=dests, orientation=orientation, banner=banner, subnet=subnet, max=maxData, dataColumn=dataColumn, hRatio=hRatio)
toc()