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

suppressMessages(library(tictoc))
suppressMessages(library(circlize))
suppressMessages(library(dplyr))
suppressMessages(library(bitops))
suppressMessages(library(tools))
suppressMessages(library(anytime))
suppressMessages(library(foreach))
suppressMessages(library(doParallel))
suppressMessages(library(grid))
suppressMessages(library(png))
suppressMessages(library(ggplot2))
suppressMessages(library(gridExtra))
suppressMessages(library(stringr))
suppressMessages(library(data.table))
suppressMessages(library(vroom))
library(profvis)

tic()
coreCount <- detectCores()
registerDoParallel(cores=coreCount-4) # May be using too many cores... but so much power!!
show(coreCount-4)

# Add Destination IPs jutting out orthogonally from the perimeter of the circle's sectors

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
  profvis({
  outlierFile <- "/data/circlePlots/old/test_data/25_outliers.tsv"
  fileType <- ".jpeg"
  sortKey <- "cluster"
  # Read in the dataFile and the outlierFile
  outliers.columns.all <- c("TEND","PROTOCOL","DPORT","SIP","PASS","clusterCenter","threatLevel")
  outliers.columns.types <- cols(TEND = "i", PROTOCOL = "c", DPORT = "i", SIP = "c", PASS = "i", clusterCenter = "i", threatLevel = "n")
  outliers <- vroom(outlierFile, delim = "\t", quote = '', altrep = TRUE, escape_double = FALSE, col_names = outliers.columns.all, col_types = outliers.columns.types, skip = 1) %>% as.data.frame()
  dataFile <- gsub("outliers", "InOut", outlierFile)
  if (!file.exists(dataFile)) {
    stop(paste0(outlierFile, " does not have a corresponding InOut file: ", dataFile))
  }
  data.columns.all <- c("TEND","SIP","DIP","FlowCount","ByteCount","PacketCount","RByteCount","RPacketCount")
  data.columns.types <- cols(TEND = "i", SIP = "c", DIP = "c", FlowCount = "i", ByteCount = "i", PacketCount = "i", RByteCount = "i", RPacketCount = "i")
  df <- vroom(dataFile, delim = "\t", quote = '', altrep = TRUE, escape_double = FALSE, col_names = data.columns.all, col_types = data.columns.types, skip = 1) %>% as.data.frame()
  
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
  uniqueSources <- outliers # %>% select(SIP)
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
    if (packetMax == 0) {
      packetMax <- 1
    } else {
      packetMax <- packetMax*2
    }
  }
  
  # Set yRange
  yRange <- c(packetMin, packetMax)
  
  #show(uniqueSources)
  #51.159.59.122 is at i=9 on 26452960_outliers.tsv
  
  plot.list <- foreach (i = 1:nrow(uniqueSources)) %dopar% {
    profvis({
    i = 25
    tempName <- tempfile(pattern = "outlier", tmpdir = tempdir(), fileext = ".png") # generate a temporary filename
    png(tempName, width = 480, height = 480)
    #show(uniqueSources$SIP[i])
    show(uniqueSources)
    
    # Gathering all rows from which data was transferred to or from the source IP, sorted by destination IP
    connections <- df %>% filter(SIP == uniqueSources$SIP[i]) %>% arrange(DIP)
    connectionMapping <- connections %>% distinct(DIP)  %>% mutate(sector = row_number()+1) # row_number+1 = section in circle plot
    dataTableMapping <- as.data.table(connectionMapping)
    setkey(dataTableMapping,DIP)
    #df <- df %>% filter(SIP != uniqueSources$SIP[i]) # Only useful if single-threaded
    
    destinationCount <- connections %>% distinct(DIP) %>% tally()
    factors <- c(1:(destinationCount$n[1] + 1)) # Weird syntax for finding the total number of slices in circle plot
    source <- as.character(uniqueSources$SIP[i]) # Grabbing the source IP
    numFactors <- as.integer(destinationCount$n[1] + 1)
    
    #show(paste(numFactors, " ", "started working"))
    
    # Do some formatting for circlize
    par(mar = c(0.5, 0.5, 1, 0.5), cex.main=1.9)
    circos.par(cell.padding = c(0, 0, 0, 0), start.degree = 90, gap.degree = min(1, 360/(2*numFactors)))
    if (numFactors > 300) {
      numFactors <- numFactors-1
      sector.widths = c(1/numFactors, 1-(1/numFactors))
      circos.initialize(factors = c(1,2), xlim = c(1,numFactors), sector.width = sector.widths)
      circos.trackPlotRegion(ylim = yRange, force.ylim = TRUE, bg.border = "#BDBDBD")
      # Source sector uses #ffff66, which is less intense than "yellow", but slightly more intense than #ffff99
      circos.updatePlotRegion(sector.index = 1, track.index = 1, bg.col = "#ffff66", bg.border = "#BDBDBD")
      
      y <- c(yRange[1], yRange[2])
      # grey0 is basically black, grey100 is verging on white. I'll make 100 sectors use grey80, and >2500 sectors use gray0
      if (numFactors >= 2500) { # darkest grey for any number of destinations greater than 2500
        color <- "grey0"
      } else { # use a scale for anything less than 2500 destinations
        greyNumber <- 60 - as.integer(((numFactors-100)/2400)*60) # 2500 will use grey0, 100 will use grey80
        color <- paste0("grey",greyNumber)
      }
      for (j in 1:numFactors) { # draw the destiation lines
        circos.lines(x=c(j,j), y=y, sector.index = 2, col = color)
      }
    } else {
      circos.initialize(factors = factors, xlim = xRange)
      circos.trackPlotRegion(ylim = yRange, force.ylim = TRUE, bg.border = "#BDBDBD")
      # Source sector uses #ffff66, which is less intense than "yellow", but slightly more intense than #ffff99
      circos.updatePlotRegion(sector.index = 1, track.index = 1, bg.col = "#ffff66", bg.border = "#BDBDBD")
    }
    
    if (sortKey == "cluster") {
      cluster <- uniqueSources$clusterCenter[i]
      modTitle <- paste(source, "--", cluster)
      title(main=modTitle, line=-0.5)
    } else if (sortKey == "threat") {
      threat <- uniqueSources$threatLevel[i]
      modTitle <- paste(source, "--", signif(threat, digits = 2))
      title(main=modTitle, line=-0.5)
    } else {
      title(main=source, line=-0.5)
    }
    
    #tic()
    # Only draw points if they are visible on plot, if there are 200 or mor sections, don't
    if (numFactors <= 300) {
      if (numFactors <= 150) {
        for (j in 1:nrow(connections)) {
          currentFactor <- dataTableMapping[.(connections$DIP[j]), nomatch = 0L]$sector[1]
          circos.points(x = connections$TEND[j], y = connections$PacketCount[j], sector.index = 1, col = "#7B3294", pch = 20)
          if (connections$RPacketCount[j] != 0) {
            circos.points(x = connections$TEND[j], y = connections$RPacketCount[j], sector.index = currentFactor, col = "#7B3294", pch = 20)
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#5AB4AC")
          } else {
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#D8B365")
          }
        }
      } else {
        for (j in 1:nrow(connections)) {
          currentFactor <- dataTableMapping[.(connections$DIP[j]), nomatch = 0L]$sector[1]
          if (connections$RPacketCount[j] != 0) {
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#5AB4AC")
          } else {
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#D8B365")
          }
        }
      }
    } else {
      connectionsRows <- nrow(connections)
      lastColor <- FALSE
      beginningSector <- dataTableMapping[.(connections$DIP[1]), nomatch = 0L]$sector[1]-1
      lastSector <- beginningSector
      tempSector <- -1
      j <- 1
      firstIteration <- TRUE
      while (j <= connectionsRows) {
        seenTeal <- FALSE
        for (k in j:connectionsRows) {
          #tic()
          #dip <- connections$DIP[k]
          #tempSector <- dataTableMapping[dip]$sector[1]-1
          tempSector <- (connectionMapping %>% filter(DIP==connections$DIP[k]))$sector[1]-1
          #tempSector <- dataTableMapping[.(connections$DIP[k]), nomatch = 0L]$sector[1]-1
          #tempSector <- dataTableMapping[.(dataTableConnections$DIP[k]), nomatch = 0L]$sector[1]-1
          #tempSector <- dataTableMapping[.(dataTableConnections[k,DIP]), nomatch = 0L]$sector[1]-1
          #toc()
          if (tempSector == lastSector) {
            if (connections$RPacketCount[k] != 0) {
              seenTeal <- TRUE
            }
          } else {
            j <- k
            break
          }
          if (k == connectionsRows) {
            j <- connectionsRows
          }
        }
        
        if (firstIteration) {
          lastColor <- seenTeal
          firstIteration <- FALSE
        }
        
        if (j != connectionsRows) {
          if (lastColor == seenTeal) {
            lastSector <- tempSector
            next
          } else {
            if (lastColor) {
              #show("drawing teal")
              circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#5AB4AC")
              #show(c(beginningSector, lastSector))
              beginningSector <- tempSector
              lastSector <- tempSector
              lastColor <- seenTeal
            } else {
              #show("drawing amber")
              circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#D8B365")
              #show(c(beginningSector, lastSector))
              beginningSector <- tempSector
              lastSector <- tempSector
              lastColor <- seenTeal
            }
          }
        } else { # we are at the end of the dataframe
          if (lastColor == seenTeal) {
            if (lastColor) {
              circos.link(2, c(beginningSector, tempSector), 1, 0, col = "#5AB4AC")
            } else {
              circos.link(2, c(beginningSector, tempSector), 1, 0, col = "#D8B365")
            }
          } else {
            if (lastColor) {
              circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#5AB4AC")
            } else {
              circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#D8B365")
            }
            if (seenTeal) {
              circos.link(2, c(lastSector, tempSector), 1, 0, col = "#5AB4AC")
            } else {
              circos.link(2, c(lastSector, tempSector), 1, 0, col = "#D8B365")
            }
          }
          break
        }
      }
    }
    #end <- toc(quiet = TRUE)[[1]][1]
    #show(paste0(numFactors, ", ", end))
    circos.clear()
    
    # Draw boxes around plots whose source IP originates from inside CSU's network
    splitIP <- str_split(source, "\\.")
    if (splitIP[[1]][1] == "129" && splitIP[[1]][2] == "82") {
      # Taken from stack overflow, but modified to fit IP title width and height
      coord <- par("usr")
      y_mid <- par("mai")[3] / 2
      height <- 0.8
      conv <- diff(grconvertY(y = 0:1, from = "inches", to = "user"))
      
      rect(xleft = coord[1] + 0.3,
           xright = coord[2] - 0.3,
           ybottom = coord[4] - 0.01 + (y_mid * (1 - height) * conv) - 0.05,
           ytop = coord[4] + (y_mid * (1 + height) * conv),
           xpd = TRUE)
    }
    
    dev.off() # finalize and save the plot to a file
    img <- readPNG(tempName) # read back finalized plot
    plot <- rasterGrob(img, interpolate = TRUE) # this will be what is combined in plot.list
    }) # # END OF PROFVIS
  }
  
  # Use ggsave to save all png's to single file, called fileCombined (specified on line 108)
  ggsave(fileCombined, width=11, height=8.5,
         arrangeGrob(grobs=plot.list, nrow=rows, ncol=cols, top=textGrob(as.character(plotsTitle), gp=gpar(fontsize=8))))
  
  }) # END OF PROFVIS
}

# Calling the MakeCircs function
# For time-keeping purposes
#MakeCircs(outlierFile, fileType, sortType)
MakeCircs("/data/circlePlots/old/26453522_outliers.tsv", ".png", "cluster")
toc()