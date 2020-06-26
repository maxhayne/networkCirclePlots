# Check whether user has provided core count or not
if (exists(coreCount)) {
  registerDoParallel(cores=coreCount)
} else {
  registerDoParallel(cores=detectCores()-2)
}

maskIP <- function(ip, mask) {
  if (mask == "/0") {
    masked <- "X.X.X.X"
  } else if (mask == "/8") {
    splitIP <- str_split(ip, "\\.")
    maskedIP <- paste0(splitIP[[1]][1],".X.X.X")
  } else if (mask == "/16") {
    splitIP <- str_split(ip, "\\.")
    masked <- paste0(splitIP[[1]][1],".",splitIP[[1]][2],".X.X")
  } else if (mask == "/24") {
    splitIP <- str_split(ip, "\\.")
    masked <- paste0(splitIP[[1]][1],".",splitIP[[1]][2],".",splitIP[[1]][3],".X")
  } else if (mask == "/32"){
    # Do nothing, show source fully
    masked <- ip
  } else {
    print("maskIP: Mask doesn't match '/0', '/8', '/16', or '/24', masking all ('/0') by default.")
    masked <- "X.X.X.X"
  }
  return(masked)
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

outlierFileToDataFrame <- function(file) {
  if (!file.exists(file)) {
    throw(paste0("The file ", file, " does not exist."))
  }
  outliers.columns.all <- c("TEND","PROTOCOL","DPORT","SIP","PASS","clusterCenter","threatLevel")
  outliers.columns.types <- cols(TEND = "i", PROTOCOL = "c", DPORT = "i", SIP = "c", PASS = "i", clusterCenter = "i", threatLevel = "n")
  outliers <- vroom(file, delim = "\t", quote = '', altrep = TRUE, escape_double = FALSE, col_names = outliers.columns.all, col_types = outliers.columns.types, skip = 1) %>% as.data.frame()
  return(outliers)
}

linksFileToDataFrame <- function(file) {
  if (!file.exists(file)) {
    throw(paste0("The file ", file, " does not exist."))
  }
  links.columns.all <- c("TEND","SIP","DIP","FlowCount","ByteCount","PacketCount","RByteCount","RPacketCount")
  links.columns.types <- cols(TEND = "i", SIP = "c", DIP = "c", FlowCount = "i", ByteCount = "i", PacketCount = "i", RByteCount = "i", RPacketCount = "i")
  links <- vroom(file, delim = "\t", quote = '', altrep = TRUE, escape_double = FALSE, col_names = links.columns.all, col_types = links.columns.types, skip = 1) %>% as.data.frame()
  return(links)
}

makeCircsFromFile <- function(outlierFile, name=NULL, fileType="png", sortKey="ip", orientation="l", fast=TRUE, mask="/0", labels=FALSE, banner=NULL) {
  dataFile <- gsub("outliers", "links", outlierFile)
  outliers <- outlierFileToDataFrame(outlierFile)
  links <- dataFileToDataFrame(dataFile)
  
  # Title the page based on input passed from the user, else, title the page based on the epoch mintue in the file name
  # Taking epoch minute portion of filename, multiplying by 60 to get epoch seconds, passing to anytime() to get date and time
  # If this process doesn't work, title the page the name of the outliers file
  if (is.null(name)) {
    file <- file_path_sans_ext(basename(outlierFile)) # grabbing outliers file name
    name <- tryCatch(
      {
        anytime(as.integer(strsplit(file, split = "_")[[1]][1])*60)
      }, error = function(cond) {
        outlierFile
      }, warning = function(cond) {
        outlierFile
      }
    )
  } else {
    
  }
  
  
}

makeCircs <- function(outliers, links, name, fileType=".png", sortKey="ip", orientation="l", fast=TRUE, mask="/0", labels=FALSE, banner=NULL) {

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
  
  # Formatting rows and columns of circle plots in a grid
  sourceCount <- (outliers %>% tally())$n[1]
  rows = ceiling(sqrt(sourceCount))
  cols = ceiling(sourceCount/rows)
  
  # Set the working directory to the path of the outliers file, saves plots here
  filePath <- dirname(outlierFile)
  setwd(filePath)
  
  # Title the page based on input passed from the user, else, title the page based on the epoch mintue in the file name
  # Taking epoch minute portion of filename, multiplying by 60 to get epoch seconds, passing to anytime() to get date and time
  # If this process doesn't work, title the page the name of the outliers file
  file <- file_path_sans_ext(basename(outlierFile)) # grabbing outliers file name
  if (is.null(title)) {
    plotsTitle <- tryCatch(
      {
        anytime(as.integer(strsplit(file, split = "_")[[1]][1])*60)
      }, error = function(cond) {
        outlierFile
      }, warning = function(cond) {
        outlierFile
      }
    )
  } else {
    plotsTitle <- title
  }
  
  #Creating image file title to which plots will be saved
  fileCombined <- paste0(file,fileType)
  
  # Find minimum and maximum TEND, set xRange
  timeSummary <- links %>% summarize(startTime = min(TEND), endTime = max(TEND))
  if (timeSummary$startTime[1] == timeSummary$endTime[1]) { # correcting bad bounds
    xRange <- c(timeSummary$endTime[1]-30, timeSummary$endTime[1])
  } else {
    xRange <- c(timeSummary$startTime[1], timeSummary$endTime[1])
  }
  
  # Find minimum and maximum packets received or sent for a row, for y-axis configuration, set yRange
  # The first if-statement compares the maxes in PacketCount and RPacketCount, setting packetMax to the
  # greater value. The second if-statement compares minimums, and sets packetMin to the lower of the two
  packetSummary <- links %>% summarize(pMin = min(PacketCount), pMax = max(PacketCount), rpMin = min(RPacketCount), rpMax = max(RPacketCount))
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
  
  plot.list <- foreach (i = 1:nrow(outliers)) %dopar% {
    tempName <- tempfile(pattern = "outlier", tmpdir = tempdir(), fileext = ".png") # generate a temporary filename
    png(tempName, width = 700, height = 700)

    # Gathering all rows from which data was transferred to or from the source IP, sorted by destination IP
    connections <- links %>% filter(SIP == outliers$SIP[i]) %>% arrange(DIP)
    connectionMapping <- connections %>% distinct(DIP)  %>% mutate(sector = row_number()+1) # row_number+1 = section in circle plot
    destinationCount <- (connections %>% distinct(DIP) %>% tally())$n[1]
    taskCount <- (connections %>% tally())$n[1]
    source <- as.character(outliers$SIP[i]) # Grabbing the source IP
    #print(paste("Tasks for IP", source, ":",taskCount))
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
      
      if (numSectors <= 50 && taskCount < 700) { # Draw normally
        for (j in 1:nrow(connections)) {
          currentFactor <- (connectionMapping %>% filter(DIP==connections$DIP[j]))$sector[1]
          circos.points(x = connections$TEND[j], y = connections$PacketCount[j], sector.index=1, col="#7B3294", pch=19)
          if (connections$RPacketCount[j] != 0) {
            circos.points(x = connections$TEND[j], y = connections$RPacketCount[j], sector.index=currentFactor, col="#7B3294", pch=19)
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col="#5AB4AC")
          } else {
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col="#D8B365")
          }
        }
      } else if (numSectors <= 250) { # Draw chords for each sector
        groupedConnections <- connections %>% group_by(DIP) %>% 
          summarize(meanRPacketCount=mean(RPacketCount), meanPacketCount=mean(PacketCount))
        # Want chord to not take up the full xRange, but, 90%, looks less cluttered
        chordMax <- xRange[2]*0.95
        chordMin <- xRange[1] + xRange[2]*0.05
        chordRange <- c(chordMin, chordMax)
        for (j in 1:nrow(groupedConnections)) {
          currentSector <- (connectionMapping %>% filter(DIP==groupedConnections$DIP[j]))$sector[1]
          if (groupedConnections$meanRPacketCount[j] > 0) {
            circos.link(currentSector, chordRange, 1, chordRange, col="#5AB4AC")
            meanPackets <- groupedConnections$meanRPacketCount[j]
            circos.lines(x=xRange, y=c(meanPackets,meanPackets), sector.index=currentSector, col="#7B3294", lwd=2)
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
    } else { # Draw everything normally, without speedup
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
          circos.points(x = dipConnections$TEND[k], y = dipConnections$PacketCount[k], sector.index = 1, col = "#7B3294", pch=19)
          if (dipConnections$RPacketCount[k] != 0) {
            circos.points(x = dipConnections$TEND[k], y = dipConnections$RPacketCount[k], sector.index = currentSector, col = "#7B3294", pch=19)
            circos.link(currentSector, dipConnections$TEND[k], 1, dipConnections$TEND[k], col = "#5AB4AC")
          } else {
            circos.link(currentSector, dipConnections$TEND[k], 1, dipConnections$TEND[k], col = "#D8B365")
          }
        }
      }
    }
    
    # Label sectors based on their destination IP's 
    if (labels) {
      # Found that adding labels to destination sectors when there are any more than 10 results in overlapping text
      if (destinationCount <= 10) {
        for (j in 1:nrow(connectionMapping)) {
          # Suppressing b/c we want the text of the destination IP to be printed outside of the plotting region
          suppressMessages(
          circos.text(x=((xRange[2]-xRange[1])/2)+xRange[1], y=packetMax+ uy(5, "mm"), sector.index=connectionMapping$sector[j], 
                      labels=maskIP(connectionMapping$DIP[j],mask), cex=1.75, niceFacing=TRUE, facing="bending"))
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
      rect(xleft = coord[1] + 0.6,
           xright = coord[2] - 0.6,
           ybottom = coord[4] - 0.01 + (y_mid * (1 - height) * conv) - 0.01,
           ytop = coord[4] + (y_mid * (1 + height) * conv) + 0.002,
           xpd = TRUE)
    }
    
    # Masking the title of the plot
    source <- maskIP(source,mask)

    # Setting the title for each individual plot
    if (sortKey == "cluster") {
      cluster <- outliers$clusterCenter[i]
      modTitle <- paste0(source, " -- ", cluster)
      title(main=modTitle, line=-0.3)
    } else if (sortKey == "threat") {
      threat <- outliers$threatLevel[i]
      modTitle <- paste0(source, " -- ", signif(threat, digits = 2))
      title(main=modTitle, line=-0.3)
    } else {
      title(main=source, line=-0.3)
    }
    
    dev.off() # finalize and save the plot to a file
    img <- readPNG(tempName) # read back finalized plot
    plot <- rasterGrob(img, interpolate = TRUE) # this will be what is combined in plot.list
  }
  
  arrangedGrob <- arrangeGrob(grobs=plot.list, nrow=rows, ncol=cols, top=textGrob(as.character(plotsTitle), gp=gpar(fontsize=8)))
  #gtable_show_layout(arrangedGrob)
  
  # Drawing vertical lines between plots to demarcate clusters
  if (sortKey == "cluster") { # We want to draw boxes around the groupings of clusters in plot grid
    clusters <- outliers %>% group_by(clusterCenter) %>% tally() %>% arrange(desc(clusterCenter))
    iterations <- nrow(clusters)-1 # Only need to draw n-1 separators
    if (iterations > 0) {
      position <- 0
      for (i in 1:iterations) {
        position <- position + clusters$n[i]
        row <- as.integer(position/cols) + 2
        column <- position - ((row-2)*cols) + 1
        #print(paste("Row:",row,"Column:",column))
        arrangedGrob <- gtable_add_grob(arrangedGrob, 
                                        grobs=segmentsGrob(x0 = 0, y0 = 0, x1 = 0, y1 = 1, gp=gpar(lwd=3)), 
                                        t = row, l = column, b = row, r = column, name=paste0("sep",i))
      }
    }
  }
  # Use ggsave to save all png's to single file, called fileCombined (specified on line 108)
  if (orientation == "l") {
    ggsave(fileCombined, width=11, height=8.5, arrangedGrob)
  } else { # Drawing in portrait mode
    ggsave(fileCombined, width=8.5, height=11, arrangedGrob)
  }
}