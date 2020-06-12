# Need to parse command-line arguments
# Command line arguments: dataFile, outliersFile, sortType, fileType
args = commandArgs(trailingOnly=TRUE)
if (length(args) != 3) {
  stop("Three command line arguments are required. Please use full paths for now. (1) Name of outlier file containing unique sources, (2) Sorting type, which can take on three possible values -- 'ip', 'cluster', or 'threat', and (3) File type, which can take on three possible values -- 'pdf', 'png', or 'jpg'.")
}

outlierFile <- args[1]
sortType <- tolower(args[2])
fileType <- tolower(args[3])

# Double checking argument values
if (fileType == "jpg" || fileType == "jpeg") {
  fileType <- ".jpeg"
} else if (fileType == "pdf") {
  fileType <- ".pdf"
} else {
  fileType <- ".png"
}

if (sortType != "cluster" && sortType != "threat" && sortType != "ip") {
  sortType <- "ip"
}

if (!file.exists(outlierFile)) {
  stop("The outlier file provided does not exist.")
}

suppressMessages(library(circlize))
suppressMessages(library(dplyr)) 
suppressMessages(library(tictoc))
suppressMessages(library(bitops))
suppressMessages(library(tools))
suppressMessages(library(anytime))
suppressMessages(library(foreach))
suppressMessages(library(doParallel))
suppressMessages(library(grid))
suppressMessages(library(png))
suppressMessages(library(ggplot2))
suppressMessages(library(gridExtra))

coreCount <- detectCores()
registerDoParallel(cores=coreCount/2)

# Figure out how to feed iterations of the for-loop to available threads on the fly. If the loop iterations
# are chunked, and each core is fed a chunk, the worst chunk could contain 4 plots that are very time consuming
# to draw. Therefore, the speedup wouldn't be optimal.

# Add functionality for specifying which column will act as the X, which column will act as they Y, which column will
# act as the Time. Default value for X will be TEND, default value for Y will Packets (or RPackets), default value 
# for Time will be TEND.

# Add functionality for specifying the type of formatting wanted for the circleplots -- Portrait, Landscape, Square, etc.

# Add functionality for specifying the yRange -- only use min and max of PacketCount, only use min and max of RPacketCount,
# or use the max and min between the two types of packet counts.

# FINISHED
# Add functionality for generating png, pdf, or jpg images from the plots generated, which have the same name as the
# outlier file but with an extension that fits the image file type

# FINISHED
# Add functionality for taking an ouliers file (should be required), add an option for which column to sort the
# the plots on. Could sort the plots on threatLevel, clusterCenter, or perhaps a more complex (not alphabetical) sorting of 
# the source IP. If asked to sort on clusterCenter, do sort on clusterCenter, but second on threatLevel. If asked to sort
# on threatLevel, just sort on threatLevel. If nothing is specified, the default will sort on IP.

# FINISHED
# Add functionality for choosing to skip plotting the points if the number of destination IP's for each source is too large.
# Because, too many sections will obfuscate the positions of the points anyway.

# Function to read datafiles in dataframes
GetCircdat <- function(file){
  return(as.data.frame(read.table(file = file, sep = '\t', header = TRUE))) #returns a dataframe from a tsv file
}

# Function which takes an IPv4 address, converts it to a long which is sortable in the way that we want
# Originally taken from https://stackoverflow.com/questions/26512404/converting-ip-addresses-in-r
# Author: 'hrbrmstr'
ip2long <- function(ip) {
  # convert string into vector of characters
  parts <- unlist(strsplit(ip, '.', fixed=TRUE))
  # set up a function to bit-shift, then "OR" the octets
  octets <- function(x,y) bitOr(bitShiftL(x, 8), y)
  # Reduce applys a funcution cumulatively left to right
  Reduce(octets, as.integer(parts))
}

MakeCircs <- function(outlierFile, fileType=".png", sortKey="ip") {
  # Read in the dataFile and the outlierFile
  outliers <- GetCircdat(outlierFile)
  dataFile <- gsub("outliers", "InOut", outlierFile)
  if (!file.exists(dataFile)) {
    stop(paste0(outlierFile, " does not have a corresponding InOut file: ", dataFile))
  }
  df <- GetCircdat(dataFile)
  
  # If sorting on threat, that is the only column we can sort on
  if (sortKey == "threat") {
    outliers <- outliers %>% arrange(desc(threatLevel))
  } else { # If not sorting on threat, we will sort on IP, but still need to check if being asked to sort on cluster
    ipLongList <- c(nrow(outliers)) # Create vector for storing converted IP addresses
    for (i in 1:nrow(outliers)) {
      ipLong <- ip2long(as.character(outliers$SIP[i]))
      ipLongList[i] <- ipLong
    }
    outliers$ipLong <- ipLongList
    if (sortKey == "cluster") { # sort on cluster first, then on IP
      outliers <- outliers %>% arrange(desc(clusterCenter),ipLong)
    } else { # only sort on IP, which is the default behavior
      outliers <- outliers %>% arrange(ipLong)
    }
  }
  
  # Grab the column of SIPs from the outliers dataframe
  uniqueSources <- outliers %>% select(SIP)
  sourceCount <- (uniqueSources %>% tally())$n[1] # For formatting
  
  # Formatting rows and columns of circle plots in a grid
  rows = ceiling(sqrt(sourceCount))
  cols = ceiling(sourceCount/rows)
  
  # Set the working directory to the path of the outliers file, saves plots here
  filePath <- dirname(outlierFile)
  setwd(filePath)
  
  file <- file_path_sans_ext(basename(outlierFile)) # grabbing outliers file name
  # Taking epoch minute portion of filename, multiplying by 60 to get epoch seconds, passing to anytime() to get date and time
  plotsTitle <- anytime(as.integer(strsplit(file, split = "_")[[1]][1])*60)
  #Creating image file title to which plots will be saved
  fileCombined <- paste0(file,fileType)

  # Find minimum and maximum TEND, set xRange
  timeSummary <- df %>% summarize(startTime = min(TEND), endTime = max(TEND))
  if (timeSummary$startTime[1] == timeSummary$endTime[1]) { # correcting bad bounds
    xRange <- c(0, timeSummary$endTime[1])
  } else {
    xRange <- c(timeSummary$startTime[1], timeSummary$endTime[1])
  }
  
  # Find minimum and maximum packets received or sent for a row, for y-axis configuration, set yRange
  # The first if-statement compares the maxes in PacketCount and RPacketCount, setting packetMax to the
  # greater value. The second if-statement compares minimums, and sets packetMin to the lower of the two
  packetSummary <- df %>% summarize(pMin = min(PacketCount), pMax = max(PacketCount), rpMin = min(RPacketCount), rpMax = max(RPacketCount))
  # Set highest maximum
  if (packetSummary$pMax[1] > packetSummary$rpMax[1]) {
    packetMax <- packetSummary$pMax[1]
  } else {
    packetMax <- packetSummary$rpMax[1]
  }
  # Set lowest minimum
  if (packetSummary$pMin[1] < packetSummary$rpMin[1]) {
    packetMin <- packetSummary$pMin[1]
  } else {
    packetMin <- packetSummary$rpMin[1]
  }
  
  if (packetMin == packetMax) { # correct bad bounds
    packetMin <- 0
    packetMax <- packetMax*2
  }
  
  # Set yRange
  yRange <- c(packetMin, packetMax)
  
  print(paste0("xRange: ", xRange[1], "->", xRange[2])) # for debugging purposes
  print(paste0("yRange: ", yRange[1], "->", yRange[2]))
  
  plot.list <- foreach (i = 1:nrow(uniqueSources)) %dopar% {
    tempName <- tempfile(pattern = "outlier", tmpdir = tempdir(), fileext = ".png") # generate a temporary filename
    png(tempName, width = 300, height = 300)

    # Gathering all rows from which data was transferred to or from the source IP, sorted by destination IP
    connections <- df %>% filter(SIP == uniqueSources$SIP[i]) %>% arrange(DIP)
    connectionMapping <- connections %>% distinct(DIP)  %>% mutate(sector = row_number()+1) # row_number+1 = section in circle plot
    df <- df %>% filter(SIP != uniqueSources$SIP[i]) # Filtering out all the entries we just selected, for speed on subsequent ops
    
    destinationCount <- connections %>% distinct(DIP) %>% tally()
    factors <- c(1:(destinationCount$n[1] + 1)) # Weird syntax for finding the total number of slices in circle plot
    source <- as.character(uniqueSources$SIP[i]) # Grabbing the source IP
    
    # Do some formatting for circlize
    par(mar = c(0.5, 0.5, 1, 0.5))
    circos.par(cell.padding = c(0, 0, 0, 0), start.degree = 90, gap.degree = min(1, 360/(2*length(factors))))
    circos.initialize(factors = factors, xlim = xRange)
    title(main = source)

    circos.trackPlotRegion(ylim = yRange, force.ylim = FALSE, bg.border = "#BDBDBD")
    circos.updatePlotRegion(sector.index = 1, track.index = 1, bg.col = "yellow", bg.border = "#BDBDBD")
    
    # Only draw points if they are visible on plot, if there are 100 or mor sections, don't
    if (length(factors) < 100) {
      for (j in 1:nrow(connections)) {
        currentFactor <- (connectionMapping %>% filter(DIP==connections$DIP[j]))$sector[1] # sector number of DIP
        circos.points(x = connections$TEND[j], y = connections$PacketCount[j], sector.index = 1, col = "#7B3294", pch = 15)
        if (connections$RPacketCount[j] != 0) {
          circos.points(x = connections$TEND[j], y = connections$RPacketCount[j], sector.index = currentFactor, col = "#7B3294", pch = 15)
        }
      }
    }
    
    # Draw the connecting lines between sections (independent of number of sectors)
    for (j in 1:nrow(connections)) {
      currentFactor <- (connectionMapping %>% filter(DIP==connections$DIP[j]))$sector[1] # sector number of DIP
      if (connections$RPacketCount[j] == 0) {
        circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#D8B365")
      } else {
        circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#5AB4AC")
      }
    }
    circos.clear()
    dev.off() # finalize and save the plot to a file
    img <- readPNG(tempName) # read back finalized plot
    plot <- rasterGrob(img, interpolate = TRUE) # this will be what is combined in plot.list
  }
  
  # Use ggsave to save all png's to single file, called fileCombined (specified on line 108)
  ggsave(fileCombined, width=8.5, height=11,
         arrangeGrob(grobs=plot.list, nrow=rows, ncol=cols, top=textGrob(as.character(plotsTitle), gp=gpar(fontsize=8))))
}

# Calling the MakeCircs function
# For time-keeping purposes
tic()
MakeCircs(outlierFile, fileType, sortType)
toc()