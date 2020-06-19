
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
suppressMessages(library(pracma))

# For verisons of the code that are loaded once, but are query the database periodically, this may be a good solution.
# As it stands, for one-time-use, compiling the small cpp function takes 6 seconds, which is just too long.
# suppressMessages(library(Rcpp))
# tic()
# sourceCpp("helperRcpp.cpp")
# toc()

tic()
coreCount <- detectCores()
registerDoParallel(cores=coreCount-4) # May be using too many cores... but so much power!!
print(paste("Number of cores:",coreCount-4))

# Add Destination IPs jutting out orthogonally from the perimeter of the circle's sectors

# Figure out how to feed iterations of the for-loop to available threads on the fly. If the loop iterations
# are chunked, and each core is fed a chunk, the worst chunk could contain 4 plots that are very time consuming
# to draw. Therefore, the speedup wouldn't be optimal.

# Add functionality for specifying which column will act as the X, which column will act as they Y, which column will
# act as the Time. Default value for X will be TEND, default value for Y will Packets (or RPackets), default value 
# for Time will be TEND.

# FINISHED
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

MakeCircs <- function(outlierFile, fileType=".png", sortKey="ip", orientation="l", fast=TRUE, mask="/0") {

  dataFile <- gsub("outliers", "InOut", outlierFile)
  if (!file.exists(outlierFile)) {
    stop(paste0(outlierFile, " does not exist!"))
  } else if (!file.exists(dataFile)) {
    stop(paste0(outlierFile, " does not have a corresponding InOut file: ", dataFile))
  }
  
  # Read in the dataFile and the outlierFile
  outliers.columns.all <- c("TEND","PROTOCOL","DPORT","SIP","PASS","clusterCenter","threatLevel")
  outliers.columns.types <- cols(TEND = "i", PROTOCOL = "c", DPORT = "i", SIP = "c", PASS = "i", clusterCenter = "i", threatLevel = "n")
  outliers <- vroom(outlierFile, delim = "\t", quote = '', altrep = TRUE, escape_double = FALSE, col_names = outliers.columns.all, col_types = outliers.columns.types, skip = 1) %>% as.data.frame()
  
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
  
  # Taking epoch minute portion of filename, multiplying by 60 to get epoch seconds, passing to anytime() to get date and time
  # If this process doesn't work, title the page the name of the outliers file
  file <- file_path_sans_ext(basename(outlierFile)) # grabbing outliers file name
  plotsTitle <- tryCatch(
    {
      anytime(as.integer(strsplit(file, split = "_")[[1]][1])*60)
    }, error = function(cond) {
      outlierFile
    }, warning = function(cond) {
      outlierFile
    }
  )
  
  #Creating image file title to which plots will be saved
  fileCombined <- paste0(file,fileType)
  
  # Find minimum and maximum TEND, set xRange
  timeSummary <- df %>% summarize(startTime = min(TEND), endTime = max(TEND))
  if (timeSummary$startTime[1] == timeSummary$endTime[1]) { # correcting bad bounds
    xRange <- c(timeSummary$endTime[1]-30, timeSummary$endTime[1])
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
  
  plot.list <- foreach (i = 1:nrow(uniqueSources)) %dopar% {
    tempName <- tempfile(pattern = "outlier", tmpdir = tempdir(), fileext = ".png") # generate a temporary filename
    png(tempName, width = 800, height = 800)

    # Gathering all rows from which data was transferred to or from the source IP, sorted by destination IP
    connections <- df %>% filter(SIP == uniqueSources$SIP[i]) %>% arrange(DIP)
    connectionMapping <- connections %>% distinct(DIP)  %>% mutate(sector = row_number()+1) # row_number+1 = section in circle plot
    destinationCount <- (connections %>% distinct(DIP) %>% tally())$n[1]
    taskCount <- (connections %>% tally())$n[1]
    source <- as.character(uniqueSources$SIP[i]) # Grabbing the source IP
    show(paste("Tasks for IP", source, ":",taskCount))
    numSectors <- as.integer(destinationCount + 1)
    
    # Tried using data.table instead of data.frame to check for speed
    #dataTableMapping <- as.data.table(connectionMapping)
    #setkey(dataTableMapping,DIP)
    #show(paste0(numSectors," started working"))
    
    # Do some formatting for circlize
    par(mar = c(0.5, 0.5, 1, 0.5), cex.main=1.9)
    circos.par(cell.padding = c(0, 0, 0, 0), start.degree = 90, gap.degree = min(1, 360/(2*numSectors)))
    
    if (fast) {
      if (numSectors > 250) {
        destSectors <- numSectors-1
        sector.widths = c(1/(destSectors*2), 1-(1/(destSectors*2)))
        circos.initialize(factors = c(1,2), xlim = c(1,destSectors), sector.width = sector.widths)
        circos.trackPlotRegion(ylim = yRange, force.ylim = TRUE, bg.border = "#BDBDBD")
        # Source sector uses #ffff66, which is less intense than "yellow", but slightly more intense than #ffff99
        circos.updatePlotRegion(sector.index = 1, track.index = 1, bg.col = "#ffff66", bg.border = "#BDBDBD")
        y <- c(yRange[1], yRange[2])
        if (destSectors > 5000) {
          color <- "grey0"
        } else {
          greyNumber <- 95 - as.integer(((destSectors-250)/4750)*95) # 2500 will use grey0, 100 will use grey80
          color <- paste0("grey",greyNumber)
        }
        circos.updatePlotRegion(sector.index = 2, track.index = 1, bg.col = color, bg.border = "#BDBDBD")
      } else {
        factors <- c(1:numSectors)
        circos.initialize(factors = factors, xlim = xRange)
        circos.trackPlotRegion(ylim = yRange, force.ylim = TRUE, bg.border = "#BDBDBD")
        # Source sector uses #ffff66, which is less intense than "yellow", but slightly more intense than #ffff99
        circos.updatePlotRegion(sector.index = 1, track.index = 1, bg.col = "#ffff66", bg.border = "#BDBDBD")
      }
      
      if (numSectors <= 25 && taskCount < 700) { # Draw normally
        for (j in 1:nrow(connections)) {
          currentFactor <- (connectionMapping %>% filter(DIP==connections$DIP[j]))$sector[1]
          circos.points(x = connections$TEND[j], y = connections$PacketCount[j], sector.index=1, col="#7B3294", pch=20)
          if (connections$RPacketCount[j] != 0) {
            circos.points(x = connections$TEND[j], y = connections$RPacketCount[j], sector.index=currentFactor, col="#7B3294", pch=20)
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col="#5AB4AC")
          } else {
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col="#D8B365")
          }
        }
      } else if (numSectors <= 250) { # Draw chords for each sector
        groupedConnections <- connections %>% group_by(DIP) %>% 
          summarize(meanRPacketCount=mean(RPacketCount), meanPacketCount=mean(PacketCount))
        # Want chord to not take up the full xRange, but, 90%
        chordMax <- xRange[2]*0.95
        chordMin <- xRange[1] + xRange[2]*0.05
        chordRange <- c(chordMin, chordMax)
        for (j in 1:nrow(groupedConnections)) {
          currentSector <- (connectionMapping %>% filter(DIP==groupedConnections$DIP[j]))$sector[1]
          if (groupedConnections$meanRPacketCount[j] > 0) {
            circos.link(currentSector, chordRange, 1, chordRange, col="#5AB4AC")
            meanPackets <- groupedConnections$meanRPacketCount[j]
            circos.lines(x=xRange, y=c(meanPackets,meanPackets), sector.index=currentSector, col="#7B3294", lwd=1.5)
          } else {
            circos.link(currentSector, chordRange, 1, chordRange, col="#D8B365")
          }
          meanPackets <- groupedConnections$meanPacketCount[j]
          circos.lines(x=xRange, y=c(meanPackets,meanPackets), sector.index=1, col="#7B3294")
        }
      } else { # Draw chords for consecutive and same-colored sectors
        groupedConnections <- connections %>% group_by(DIP) %>% 
          summarize(meanRPacketCount=mean(RPacketCount), meanPacketCount=mean(PacketCount)) %>% 
          arrange(meanRPacketCount)
        if (groupedConnections$meanRPacketCount[1] > 0) {
          chordColor <- TRUE
        } else {
          chordColor <- FALSE
        }
        chordBegin <- 1
        for (j in 2:nrow(groupedConnections)) {
          if (groupedConnections$meanRPacketCount[j] > 0) {
            jColor <- TRUE
          } else {
            jColor <- FALSE 
          }
          if (chordColor == jColor) {
            if (j != nrow(groupedConnections)) {
              next
            } else {
              if (chordColor) {
                circos.link(2, c(chordBegin, j), 1, xRange[2]/2, col="#5AB4AC")
              } else {
                circos.link(2, c(chordBegin, j), 1, xRange[2]/2, col="#D8B365")
              }
            }
          } else {
            if (chordColor) { # Draw teal chord
              circos.link(2, c(chordBegin, j-1), 1, xRange[2]/2, col="#5AB4AC")
            } else { # Draw amber chord
              circos.link(2, c(chordBegin, j-1), 1, xRange[2]/2, col="#D8B365")
            }
            chordBegin <- j
            chordColor <- jColor
          }
        }
      }
    #   print(numSectors)
    #   tic()
    #   # Only draw points if they are visible on plot, if there are 200 or more sections, don't
    #   if (numSectors <= 250) {
    #     # This is the fast version. If we have more than 600 tasks, it will take around 5 seconds for a single plot. Let's use
    #     # that as a starting point.
    #     if (taskCount > 600) {
    #       groupingFactor <- ceiling(taskCount/600)
    #       print(paste("Grouping Factor:",groupingFactor))
    #       groupingWindow <- 0
    #       beginTime <- connections$TEND[1]
    #       endTime <- beginTime
    #       beginDIP <- connections$DIP[1]
    #       sector <- (connectionMapping %>% filter(DIP==beginDIP))$sector[1]
    #       #circos.points(x=beginTime, y=connections$PacketCount[1], sector.index=1, col = "#7B3294", pch = 20)
    #       rpc <- connections$RPacketCount[1]
    #       if (rpc != 0) {
    #         seenTeal <- TRUE
    #         #circos.points(x=beginTime, y=rpc, sector.index=sector, col = "#7B3294", pch = 20)
    #       } else {
    #         seenTeal <- FALSE
    #       }
    #       groupingWindow <- groupingWindow+1
    #       for (j in 2:nrow(connections)) {
    #         currentDIP <- connections$DIP[j]
    #         if (groupingWindow == groupingFactor || currentDIP != beginDIP || j == nrow(connections)) {
    #           timeSpan <- c(beginTime, endTime)
    #           if (seenTeal) {
    #             circos.link(sector, timeSpan, 1, timeSpan, col = "#5AB4AC")
    #             circos.points(x=endTime, y=connections$RPacketCount[j], sector.index=sector, col = "#7B3294", pch = 20)
    #             circos.points(x=endTime, y=connections$PacketCount[j], sector.index=1, col = "#7B3294", pch = 20)
    #           } else {
    #             circos.link(sector, timeSpan, 1, timeSpan, col = "#D8B365")
    #             circos.points(x=endTime, y=rpc <- connections$PacketCount[j], sector.index=1, col = "#7B3294", pch = 20)
    #           }
    #           beginTime <- connections$TEND[j]
    #           endTime <- beginTime
    #           sector <- (connectionMapping %>% filter(DIP==currentDIP))$sector[1]
    #           #circos.points(x=beginTime, y=connections$PacketCount[j], sector.index=1, col = "#7B3294", pch = 20)
    #           rpc <- connections$RPacketCount[j]
    #           if (rpc != 0) {
    #             seenTeal <- TRUE
    #             #circos.points(x=beginTime, y=rpc, sector.index=sector, col = "#7B3294", pch = 20)
    #           } else {
    #             seenTeal <- FALSE
    #           }
    #           groupingWindow <- 1
    #         } else {
    #           endTime <- connections$TEND[j]
    #           #circos.points(x=endTime, y=connections$PacketCount[j], sector.index=1, col = "#7B3294", pch = 20)
    #           rpc <- connections$RPacketCount[j]
    #           if (rpc != 0) {
    #             seenTeal <- TRUE
    #             #circos.points(x=endTime, y=rpc, sector.index=sector, col = "#7B3294", pch = 20)
    #           } else {
    #             seenTeal <- FALSE
    #           }
    #         }
    #       }
    #     } else {
    #       for (j in 1:nrow(connections)) {
    #         #currentFactor <- dataTableMapping[.(connections$DIP[j]), nomatch = 0L]$sector[1]
    #         currentFactor <- (connectionMapping %>% filter(DIP==connections$DIP[j]))$sector[1]
    #         circos.points(x = connections$TEND[j], y = connections$PacketCount[j], sector.index = 1, col = "#7B3294", pch = 20)
    #         if (connections$RPacketCount[j] != 0) {
    #           circos.points(x = connections$TEND[j], y = connections$RPacketCount[j], sector.index = currentFactor, col = "#7B3294", pch = 20)
    #           circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#5AB4AC")
    #         } else {
    #           circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col = "#D8B365")
    #         }
    #       }
    #     }
    #   } else {
    #     connectionsRows <- nrow(connections)
    #     lastColor <- FALSE
    #     beginningSector <- (connectionMapping %>% filter(DIP==connections$DIP[1]))$sector[1]-1
    #     lastSector <- beginningSector
    #     tempSector <- -1
    #     j <- 1
    #     firstIteration <- TRUE
    #     while (j <= connectionsRows) {
    #       seenTeal <- FALSE
    #       for (k in j:connectionsRows) {
    #         #tic()
    #         #tempSector <- dataTableMapping[dip]$sector[1]-1
    #         tempSector <- (connectionMapping %>% filter(DIP==connections$DIP[k]))$sector[1]-1
    #         #tempSector <- dataTableMapping[.(connections$DIP[k]), nomatch = 0L]$sector[1]-1
    #         #tempSector <- dataTableMapping[.(dataTableConnections$DIP[k]), nomatch = 0L]$sector[1]-1
    #         #tempSector <- dataTableMapping[.(dataTableConnections[k,DIP]), nomatch = 0L]$sector[1]-1
    #         #toc()
    #         if (tempSector == lastSector) {
    #           if (connections$RPacketCount[k] != 0) {
    #             seenTeal <- TRUE
    #           }
    #         } else {
    #           j <- k
    #           break
    #         }
    #         if (k == connectionsRows) {
    #           j <- connectionsRows
    #         }
    #       }
    #       
    #       if (firstIteration) {
    #         lastColor <- seenTeal
    #         firstIteration <- FALSE
    #       }
    #       
    #       if (j != connectionsRows) {
    #         if (lastColor == seenTeal) {
    #           lastSector <- tempSector
    #           next
    #         } else {
    #           if (lastColor) {
    #             #show("drawing teal")
    #             circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#5AB4AC")
    #             #show(c(beginningSector, lastSector))
    #             beginningSector <- tempSector
    #             lastSector <- tempSector
    #             lastColor <- seenTeal
    #           } else {
    #             #show("drawing amber")
    #             circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#D8B365")
    #             #show(c(beginningSector, lastSector))
    #             beginningSector <- tempSector
    #             lastSector <- tempSector
    #             lastColor <- seenTeal
    #           }
    #         }
    #       } else { # we are at the end of the dataframe
    #         if (lastColor == seenTeal) {
    #           if (lastColor) {
    #             circos.link(2, c(beginningSector, tempSector), 1, 0, col = "#5AB4AC")
    #           } else {
    #             circos.link(2, c(beginningSector, tempSector), 1, 0, col = "#D8B365")
    #           }
    #         } else {
    #           if (lastColor) {
    #             circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#5AB4AC")
    #           } else {
    #             circos.link(2, c(beginningSector, lastSector), 1, 0, col = "#D8B365")
    #           }
    #           if (seenTeal) {
    #             circos.link(2, c(lastSector, tempSector), 1, 0, col = "#5AB4AC")
    #           } else {
    #             circos.link(2, c(lastSector, tempSector), 1, 0, col = "#D8B365")
    #           }
    #         }
    #         break
    #       }
    #     }
    #   }
    } else { # Draw everything normall, without speedup
      factors <- c(1:numSectors)
      circos.initialize(factors = factors, xlim = xRange)
      circos.trackPlotRegion(ylim = yRange, force.ylim = TRUE, bg.border = "#BDBDBD")
      # Source sector uses #ffff66, which is less intense than "yellow", but slightly more intense than #ffff99
      circos.updatePlotRegion(sector.index = 1, track.index = 1, bg.col = "#ffff66", bg.border = "#BDBDBD")
      # Just do a for loop on the connectionMapping and then filter connections based on that
      for (j in 1:nrow(connectionMapping)) {
        currentSector <- connectionMapping$sector[j]
        dipConnections <- connections %>% filter(DIP==connectionMapping$DIP[j])
        connections <- connections %>% filter(DIP != connectionMapping$DIP[j])
        for (k in 1:nrow(dipConnections)) {
          circos.points(x = dipConnections$TEND[k], y = dipConnections$PacketCount[k], sector.index = 1, col = "#7B3294", pch = 20)
          if (dipConnections$RPacketCount[k] != 0) {
            circos.points(x = dipConnections$TEND[k], y = dipConnections$RPacketCount[k], sector.index = currentSector, col = "#7B3294", pch = 20)
            circos.link(currentSector, dipConnections$TEND[k], 1, dipConnections$TEND[k], col = "#5AB4AC")
          } else {
            circos.link(currentSector, dipConnections$TEND[k], 1, dipConnections$TEND[k], col = "#D8B365")
          }
        }
      }
    }
    
    circos.clear()
    
    # Drawing boxes around the titles of the plots whose SIP's are from within the cluster's network
    subnet <- str_split(file,"_")[[1]][2] 
    subIP <- substr(source,1,nchar(subnet))
    if (strcmp(subIP,subnet)) {
      # Taken from stack overflow, but modified to fit IP title width and height
      coord <- par("usr")
      y_mid <- par("mai")[3] / 2
      height <- 0.8
      conv <- diff(grconvertY(y = 0:1, from = "inches", to = "user"))
      rect(xleft = coord[1] + 0.3,
           xright = coord[2] - 0.3,
           ybottom = coord[4] - 0.01 + (y_mid * (1 - height) * conv) - 0.04,
           ytop = coord[4] + (y_mid * (1 + height) * conv),
           xpd = TRUE)
    }
    
    # Masking the titles
    if (mask == "/0") {
      source <- "X.X.X.X"
    } else if (mask == "/8") {
      splitIP <- str_split(source, "\\.")
      source <- paste0(splitIP[[1]][1],".X.X.X")
    } else if (mask == "/16") {
      splitIP <- str_split(source, "\\.")
      source <- paste0(splitIP[[1]][1],".",splitIP[[1]][2],".X.X")
    } else if (mask == "/24") {
      splitIP <- str_split(source, "\\.")
      source <- paste0(splitIP[[1]][1],".",splitIP[[1]][2],".",splitIP[[1]][3],".X")
    } else if (mask == "/32"){
      # Do nothing, show source fully
    } else {
      print("Mask doesn't match '/0', '/8', '/16', or '/24', masking all ('/0') by default.")
      source <- "X.X.X.X"
    }
    
    # Setting the titles
    if (sortKey == "cluster") {
      cluster <- uniqueSources$clusterCenter[i]
      modTitle <- paste0(source, "--", cluster)
      title(main=modTitle, line=-0.7)
    } else if (sortKey == "threat") {
      threat <- uniqueSources$threatLevel[i]
      modTitle <- paste0(source, "--", signif(threat, digits = 2))
      title(main=modTitle, line=-0.7)
    } else {
      title(main=source, line=-0.7)
    }
    
    dev.off() # finalize and save the plot to a file
    img <- readPNG(tempName) # read back finalized plot
    plot <- rasterGrob(img, interpolate = TRUE) # this will be what is combined in plot.list
  }
  
  # Use ggsave to save all png's to single file, called fileCombined (specified on line 108)
  if (orientation == "l") {
    ggsave(fileCombined, width=11, height=8.5,
           arrangeGrob(grobs=plot.list, nrow=rows, ncol=cols, top=textGrob(as.character(plotsTitle), gp=gpar(fontsize=8))))
  } else {
    ggsave(fileCombined, width=8.5, height=11,
           arrangeGrob(grobs=plot.list, nrow=rows, ncol=cols, top=textGrob(as.character(plotsTitle), gp=gpar(fontsize=8))))
  }
}

# Calling the MakeCircs function
# For time-keeping purposes
MakeCircs(outlierFile, fileType, sortType, fast=FALSE, mask="/16")
#MakeCircs("/data/circlePlots/old/26453522_outliers.tsv", ".png", "cluster")
toc()