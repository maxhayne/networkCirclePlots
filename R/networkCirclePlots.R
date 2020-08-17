# Import libraries
if (!suppressMessages(require("pacman"))) stop("Error: package 'pacman' must be installed.")
pacman::p_load("pracma","doParallel","circlize","dplyr","bitops", "tictoc",
               "tools","anytime","grid","png","ggplot2","gridExtra","stringr",
               "vroom","gtable","optparse","dtplyr","data.table", install=FALSE)

# Check if they loaded
isLoaded <- pacman::p_isloaded("pracma","doParallel","circlize","dplyr","bitops", "tictoc",
                   "tools","anytime","grid","png","ggplot2","gridExtra","stringr",
                   "vroom","gtable","optparse","dtplyr","data.table")

# Stop if loading was incomplete
if (FALSE %in% isLoaded) {
  stop("A necessary package isn't installed. See warning message above from 'pacman'. If no warning message is present, check the top of this script for the package list.")
}

registerDoParallel(cores=detectCores()-2) # Register number of cores w/ doParallel

# Change core count based on user's preference
changeCoreCount <- function(newCoreCount) {
  if (!is.numeric(newCoreCount)) {
    cat("Error: must provide an integer value for the new core count. Nothing has changed.")
    return()
  } else {
    if (newCoreCount%%1 != 0) {
      cat("Error: new core count must be an integer value.")
      return()
    }
    if (newCoreCount > detectCores()) {
      cat("Requested core count is greater than the number of cores the machine has. Set to max.")
      stopImplicitCluster()
      registerDoParallel(cores=detectCores())
    } else if (newCoreCount < 1) {
      cat("Requested core count is less than 1. Set to min.")
      stopImplicitCluster()
      registerDoParallel(cores=1)
    } else {
      stopImplicitCluster()
      registerDoParallel(cores=newCoreCount)
    }
  }
}

# Mask IPs to user's preference
maskIP <- function(ip, mask) {
  if (mask == "/0") {
    masked <- "X.X.X.X"
  } else if (mask == "/8") {
    splitIP <- str_split(ip, "\\.")
    masked <- paste0(splitIP[[1]][1],".X.X.X")
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
    cat("maskIP: Mask doesn't match '/0', '/8', '/16', or '/24', masking all ('/0') by default.")
    masked <- "X.X.X.X"
  }
  return(masked)
}

# Function which takes an IPv4 address, converts it to a long which is sortable in the way that we want
# Originally taken from https://stackoverflow.com/questions/26512404/converting-ip-addresses-in-r
ip2long <- function(ip) {
  # convert string into vector of characters
  parts <- unlist(strsplit(ip, '.', fixed=TRUE))
  # set up a function to bit-shift, then "OR" the octets
  octets <- function(x,y) bitOr(bitShiftL(x, 8), y)
  # Reduce applys a funcution cumulatively left to right
  Reduce(octets, as.integer(parts))
}

# Convert outliers file to data.frame
outlierFileToDataFrame <- function(file) {
  if (!file.exists(file)) {
    stop(paste0("The file ", file, " does not exist."))
  }
  outliers.columns.all <- c("TEND","PROTOCOL","DPORT","SIP","PASS","clusterCenter","threatLevel")
  outliers.columns.types <- cols(TEND = "i", PROTOCOL = "c", DPORT = "i", SIP = "c", PASS = "i", clusterCenter = "n", threatLevel = "n")
  outliers <- vroom(file, delim = "\t", quote = '', altrep = TRUE, escape_double = FALSE, col_names = outliers.columns.all, col_types = outliers.columns.types, skip = 1) %>% as.data.frame()
  return(outliers)
}

# Convert links file to data.frame
linksFileToDataFrame <- function(file) {
  if (!file.exists(file)) {
    stop(paste0("The file ", file, " does not exist."))
  }
  links.columns.all <- c("TEND","SIP","DIP","FlowCount","ByteCount","PacketCount","RByteCount","RPacketCount")
  links.columns.types <- cols(TEND = "i", SIP = "c", DIP = "c", FlowCount = "i", ByteCount = "i", PacketCount = "i", RByteCount = "i", RPacketCount = "i")
  links <- vroom(file, delim = "\t", quote = '', altrep = TRUE, escape_double = FALSE, col_names = links.columns.all, col_types = links.columns.types, skip = 1) %>% as.data.frame()
  return(links)
}

# Check validity of links data.frame
checkLinksDataFrame <- function(links) {
  columnNames <- colnames(links)
  correctColumnNames <- c("TEND","SIP","DIP","FlowCount","ByteCount","PacketCount","RByteCount","RPacketCount")
  diff <- setdiff(correctColumnNames, columnNames)
  if (length(diff) > 0) {
    msg <- paste0("The 'links' dataframe must contain these columns (case-sensitive): ",  paste(diff,collapse=","), ".")
    stop(msg)
  }
  positions <- which(correctColumnNames %in% columnNames)
  columnTypes <- as.vector(sapply(links, class))
  correctColumnTypes <- c("integer", "character", "character", "integer", "integer", "integer", "integer", "integer")
  for (i in 1:length(correctColumnTypes)) {
    if (!strcmp(correctColumnTypes[i], columnTypes[positions[i]])) {
      msg <- paste0("In the 'links' data frame: column '", columnNames[positions[i]], "' must be of type '", correctColumnTypes[i], "'. It is of type '", columnTypes[positions[i]],"'.")
      stop(msg)
    }
  }
}

# Check validity of outliers data.frame
checkOutliersDataFrame <- function(outliers) {
  columnNames <- colnames(outliers)
  correctColumnNames <- c("TEND","PROTOCOL","DPORT","SIP","PASS","clusterCenter","threatLevel")
  diff <- setdiff(correctColumnNames, columnNames)
  if (length(diff) > 0) {
    msg <- paste0("The 'outliers' dataframe must contain these columns (case-sensitive): ", paste(diff,collapse=","), ".")
    stop(msg)
  }
  positions <- which(correctColumnNames %in% columnNames)
  columnTypes <- as.vector(sapply(outliers, class))
  # Made correct types a list so each column could have multiple types, if necessary
  correctColumnTypes <- list(c("integer"), c("character"), c("integer"), c("character"), c("integer"), c("integer","numeric"), c("numeric"))
  for (i in 1:length(correctColumnTypes)) {
    match <- FALSE
    for (j in 1:length(correctColumnTypes[[i]])) {
      if (strcmp(correctColumnTypes[[i]][j],columnTypes[positions[i]])) {
        match <- TRUE
        break
      }
    }
    if (!match) {
      msg <- paste0("In the 'outliers' data frame: column '", columnNames[positions[i]], "' must be of type(s) '", paste(correctColumnTypes[[i]],collapse=","), "'. It is of type '", columnTypes[positions[i]],"'.")
      stop(msg)
    }
  }
}

# Check validity of fileType
checkFileType <- function(fileType) {
  types <- c("jpg", "jpeg", "png", "pdf")
  lowerFileType <- tolower(fileType)
  if (!(lowerFileType %in% types)) {
    msg <- paste0("The fileType must be one of the following: ", paste(types, collapse=","), ".")
    stop(msg)
  }
  return(lowerFileType)
}

# Check validity of orientation (aspect-ratio)
checkOrientation <- function(orientation) {
  lowerOrientation <- tolower(orientation) 
  if (!strcmp(lowerOrientation, "l") && !strcmp(lowerOrientation, "p") && !strcmp(lowerOrientation,"le") && !strcmp(lowerOrientation,"pe")) {
    msg <- "The orientation must be 'l' (landscape), 'p' (portrait), 'le' (landscape extended), or 'pe' (portrait extended)."
    stop(msg)
  }
  return(lowerOrientation)
}

# Check validity of sortType
checkSortType <- function(sortType) {
  types <- c("cluster", "threat", "ip")
  lowerSortType <- tolower(sortType)
  if (!(lowerSortType %in% types)) {
    msg <- paste0("The sortType must be one of the following: ", paste(types, collapse=","), ".")
    stop(msg)
  }
  return(lowerSortType)
}

# Check validity of mask
checkMask <- function(mask) {
  types <- c("/0","/8","/16","/24","/32")
  if (!(mask %in% types)) {
    msg <- paste0("The mask must be one of the following: ", paste(types, collapse=","), ".")
    stop(msg)
  }
}

# Check validity of hRatio
checkHRatio <- function(hRatio) {
  if (is.numeric(hRatio) && hRatio >= 0 && hRatio <= 1) {
    return(hRatio)
  } else {
    msg <- "hRatio must be a decimal number between 0 and 1 (inclusive)."
    stop(msg)
  }
}

# Check validity of max value
checkMax <- function(max) {
  if (!is.null(max)) {
    if (!is.numeric(max)) {
      msg <- "The max value must be numeric."
      stop(msg)
    }
  }
}

# Function to find best dimensions for plot grid which will be closest to 8.5 by 11 page size
bestDimensions <- function(sourceCount) {
  if (sourceCount == 1) {
    return(c(1,1))
  }
  ratio <- 8.5/11
  bestDelta <- 1000
  dim <- c(0,0)
  for (i in 1:ceiling(sqrt(sourceCount))) {
    tempFactor <- ceiling(sourceCount/i)
    tempRatio1 <- tempFactor/i
    tempRatio2 <- i/tempFactor
    difference1 <- abs(tempRatio1-ratio)
    difference2 <- abs(tempRatio2-ratio)
    # A little verbose, but wanted always the smaller factor in dim[1], the larger in dim[2]
    if (difference1 < bestDelta) {
      if (i <= tempFactor) {
        dim[1] <- i
        unused <- tempFactor
      } else {
        dim[1] <- tempFactor
        unused <- i
      }
      dim[2] <- unused
      bestDelta <- difference1
    } 
    if (difference2 < bestDelta) {
      if (i <= tempFactor) {
        dim[1] <- i
        unused <- tempFactor
      } else {
        dim[1] <- tempFactor
        unused <- i
      }
      dim[2] <- unused
      bestDelta <- difference2
    }
  }
  return(dim)
}

# Function which takes outlier filename instead of data.frames, then calls makeCircles()
makeCirclesFromFile <- function(outlierFile, name=NULL, fileType="jpg", sortType="ip", orientation="l", fast=TRUE, mask="/0", dests=FALSE, dataColumn="packet", hRatio=0.7, banner=NULL, subnet=NULL, max=NULL) {
  outliers <- outlierFileToDataFrame(outlierFile)
  linksFile <- gsub("outliers.tsv", "links.tsv", outlierFile)
  links <- linksFileToDataFrame(linksFile)
  
  file <- file_path_sans_ext(basename(outlierFile)) # grabbing outliers file name
  if (is.null(name)) {
    name <- paste0(dirname(outlierFile), "/", file, ".", fileType)
  }
  
  if (is.null(banner)) {
    banner <- tryCatch(
      {
        anytime(as.integer(strsplit(file, split = "_")[[1]][1])*60)
      }, error = function(cond) {
        file
      }, warning = function(cond) {
        file
      }
    )
  }
  
  # Check for subnet in outlier filename
  if (is.null(subnet)) {
    if (str_count(file, pattern="_") > 1) { # Only check for subnet in filename if in this format: TIME_SUBNET_outliers
      subnet <- tryCatch(
        {
          str_split(file,"_")[[1]][2]
        }, error = function(cond) {
          NULL
        }, warning = function(cond) {
          NULL
        }
      )
    } else {
      subnet <- NULL
    }
  }
  # Call the main function with the provided parameters
  makeCircles(outliers, links, name, banner=banner, fileType=fileType, sortType=sortType, orientation=orientation, fast=fast, mask=mask, dests=dests, subnet=subnet, max=max, dataColumn=dataColumn, hRatio=hRatio)
}

# Main function for drawing circle plots from data frames
makeCircles <- function(outliers, links, name, fileType="jpg", sortType="ip", orientation="l", fast=TRUE, mask="/0", dests=FALSE, dataColumn="packet", hRatio=0.7, banner=NULL, subnet=NULL, max=NULL) {
  # Checking parameters for their correct types
  checkOutliersDataFrame(outliers)
  checkLinksDataFrame(links)
  fileType <- checkFileType(fileType)
  sortType <- checkSortType(sortType)
  orientation <- checkOrientation(orientation)
  checkMask(mask)
  hRatio <- checkHRatio(hRatio)
  checkMax(max)
  
  # Let the user know if the outliers data frame and the links data frame don't contain matching SIPs
  differences <- length(setdiff(links$SIP,outliers$SIP))
  if (differences != 0) {
    cat(paste("Warning:", differences, "SIPs in the links data frame don't match the SIPs in the outliers data frame.\n"))
  }

  # Creating generalized variables which can be used in the same context to specify different columns in 'dplyr'
  # Also specifying link colors so that we can allow 'FlowCount' to only use a single color
  if (strcmpi(dataColumn, "packet")) {
    colName <- "PacketCount"
    RcolName <- "RPacketCount"
    dataColumn <- as.name(colName)
    RdataColumn <- as.name(RcolName)
    linkColors <- c("#5ab4ac","#D8B365") # Teal and Amber
  } else if (strcmpi(dataColumn, "byte")) {
    colName <- "ByteCount"
    RcolName <- "RByteCount"
    dataColumn <- as.name(colName)
    RdataColumn <- as.name(RcolName)
    linkColors <- c("#5ab4ac","#D8B365") # The first color means a reply, the second means no reply
  } else if (strcmpi(dataColumn, "flow")) {
    colName <- "FlowCount"
    RcolName <- "FlowCount"
    dataColumn <- as.name(colName)
    RdataColumn <- as.name(RcolName)
    linkColors <- c("#756bb1","#756bb1") # Same color twice
  } else {
    stop("dataColumn must be equal to 'packet', 'byte' or 'flow' (to represent PacketCount, ByteCount, or FlowCount)")
  }

  # If sorting on threat, that is the only column we can sort on
  if (strcmp(sortType,"threat")) {
    outliers <- outliers %>% arrange(desc(threatLevel))
  } else { # If not sorting on threat, we will sort on IP, but still need to check if being asked to sort on cluster
    ipLongList <- c(nrow(outliers)) # Create vector for storing converted IP addresses
    for (i in 1:nrow(outliers)) {
      ipLong <- ip2long(as.character(outliers$SIP[i]))
      ipLongList[i] <- ipLong
    }
    outliers$ipLong <- ipLongList
    if (strcmp(sortType,"cluster")) { # sort on cluster first, then on IP
      outliers <- outliers %>% arrange(desc(clusterCenter),ipLong)
    } else { # only sort on IP, which is the default behavior
      outliers <- outliers %>% arrange(ipLong)
    }
  }
  
  # Set the working directory to the path of the name provided by the user
  filePath <- dirname(name)

  # If banner is provided, use the banner. If no banner is provided, try to extract information about the time
  # the data was taken from the name of the output file passed by the user. If the name of the file given by
  # the user is not in the format '<EpochMinute>_outliers', banner the page the name passed by the user.
  file <- file_path_sans_ext(basename(name)) # grabbing name of the output file
  if (is.null(banner)) {
    banner <- tryCatch(
      {
        anytime(as.integer(strsplit(file, split = "_")[[1]][1])*60)
      }, error = function(cond) {
        file
      }, warning = function(cond) {
        file
      }
    )
  }
  
  # Creating image file title to which plots will be saved
  fileCombined <- paste0(file,".",fileType)
  
  # Find min and max timstamps in links file, will standardize the range of the x-axis for all plots
  timeSummary <- links %>% summarize(startTime = min(TEND), endTime = max(TEND))
  if (timeSummary$startTime[1] == timeSummary$endTime[1]) { # correcting bad bounds
    xRange <- c(timeSummary$endTime[1]-30, timeSummary$endTime[1])
  } else {
    xRange <- c(timeSummary$startTime[1], timeSummary$endTime[1])
  }
  
  xMiddle <- xRange[1] + ((xRange[2]-xRange[1])/2)

  # Find minimum and maximum data received or sent for a row, for y-axis configuration, set yRange
  dataSummary <- links %>% summarize(dMin = min(!!dataColumn), dMax = max(!!dataColumn), rdMin = min(!!RdataColumn), rdMax = max(!!RdataColumn))
  # Set highest maximum
  if (dataSummary$dMax[1] > dataSummary$rdMax[1]) {
    dataMax <- dataSummary$dMax[1]
  } else {
    dataMax <- dataSummary$rdMax[1]
  }
  # Set lowest minimum
  if (dataSummary$dMin[1] < dataSummary$rdMin[1]) {
    dataMin <- dataSummary$dMin[1]
  } else {
    dataMin <- dataSummary$rdMin[1]
  }
  if (dataMin == dataMax) { # correct bad bounds
    dataMin <- 0
    if (dataMax == 0) {
      dataMax <- 1
    } else {
      dataMax <- dataMax*2
    }
  }
  
  # Set yRange
  yRange <- c(dataMin, dataMax)
  
  if (is.null(max)) {max <- dataMax+1} # Set maximum to never be taken into account
  
  # If fast plotting is enabled, there is a ceiling on how long the plot will take to draw, so pre-allocating
  # plots to cores will improve performance. If fast plotting is disabled, pre-allocating may assign one core
  # an unfair number of complex plots. This will slow the plotting process.
  if (fast) {
    mcoptions <- list(preschedule=TRUE)
  } else {
    mcoptions <- list(preschedule=FALSE)
  }
  plot.list <- foreach (i = 1:nrow(outliers), .options.multicore=mcoptions, .verbose=FALSE) %dopar% {
    tempName <- tempfile(pattern = "outlier", tmpdir = tempdir(), fileext = ".png") # generate a temporary filename
    png(tempName, width = 700, height = 700)
    
    # Gathering all rows from which data was transferred to or from the source IP, sorted by destination IP
    connections <- links %>% filter(SIP == outliers$SIP[i]) %>% arrange(DIP)
    connectionMapping <- connections %>% group_by(DIP) %>% 
      summarize(meanRDataCount=mean(!!RdataColumn), meanDataCount=mean(!!dataColumn), .groups="keep") %>% 
      arrange(meanRDataCount)
    connectionMapping$sector <- c(2:(nrow(connectionMapping)+1)) # Adding a column which is current row#+1
    destinationCount <- nrow(connections %>% distinct(DIP))
    taskCount <- nrow(connections)
    source <- as.character(outliers$SIP[i]) # Grabbing the source IP
    numSectors <- as.integer(destinationCount + 1)
    
    # Do some formatting for circlize
    par(mar = c(0.5, 0.5, 1, 0.5), cex.main=1.9)
    circos.par(cell.padding = c(0, 0, 0, 0), start.degree = 90, gap.degree = min(1, 360/(2*numSectors)))
    
    if (fast) {
      if (numSectors > 250) {
        sector.widths = c(1/(destinationCount*2), 1-(1/(destinationCount*2)))
        circos.initialize(factors = c(1,2), xlim = c(1,destinationCount), sector.width = sector.widths)
        circos.trackPlotRegion(ylim = yRange, force.ylim = TRUE, bg.border = "#BDBDBD")
        # Source sector uses #ffff66, which is less intense than "yellow", but slightly more intense than #ffff99
        circos.updatePlotRegion(sector.index = 1, track.index = 1, bg.col = "#ffff66", bg.border = "#BDBDBD")
        y <- c(yRange[1], yRange[2])
        if (destinationCount > 5000) {
          color <- "grey0"
        } else {
          greyNumber <- 95 - as.integer(((destinationCount-250)/4750)*95) # 2500 will use grey0, 100 will use grey80
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
      
      if (numSectors <= 99 && taskCount < 700) { # Draw normally
        for (j in 1:nrow(connections)) {
          currentFactor <- (connectionMapping %>% filter(DIP==connections$DIP[j]))$sector[1]
          if (connections[[dataColumn]][j] >= max || connections[[RdataColumn]][j] >= max) {
            circos.points(x = connections$TEND[j], y = connections[[dataColumn]][j], sector.index=1, col="#7B3294", pch=19)
            if (connections[[dataColumn]][j] >= max) {suppressMessages(circos.points(x = connections$TEND[j], y = dataMax + uy(2, "mm"), sector.index=1, col="red", pch=19))}
            if (connections[[RdataColumn]][j] != 0) {
              circos.points(x = connections$TEND[j], y = connections[[RdataColumn]][j], sector.index=currentFactor, col="#7B3294", pch=19)
              if (connections[[RdataColumn]][j] >= max) {suppressMessages(circos.points(x = connections$TEND[j], y = dataMax + uy(2, "mm"), sector.index=currentFactor, col="red", pch=19))}
            }
            circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], lwd=2, col="red", h.ratio=hRatio)
          } else {
            circos.points(x = connections$TEND[j], y = connections[[dataColumn]][j], sector.index=1, col="#7B3294", pch=19)
            if (connections[[RdataColumn]][j] != 0) {
              circos.points(x = connections$TEND[j], y = connections[[RdataColumn]][j], sector.index=currentFactor, col="#7B3294", pch=19)
              circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col=linkColors[1], h.ratio=hRatio)
            } else {
              circos.link(currentFactor, connections$TEND[j], 1, connections$TEND[j], col=linkColors[2], h.ratio=hRatio)
            }
          }
        }
      } else if (numSectors <= 250) { # Draw chords for each sector
        groupedConnections <- connections %>% group_by(DIP) %>% 
          summarize(meanRDataCount=mean(!!RdataColumn), meanDataCount=mean(!!dataColumn), maxRCount=sum(!!RdataColumn>=max), maxCount=sum(!!dataColumn>=max), .groups="keep") %>%
          arrange(meanRDataCount)
        # Want chord to not take up the full xRange, but, 90%, looks less cluttered
        chordMax <- xRange[2]*0.95
        chordMin <- xRange[1] + xRange[2]*0.05
        chordRange <- c(chordMin, chordMax)
        for (j in 1:nrow(groupedConnections)) {
          currentSector <- (connectionMapping %>% filter(DIP==groupedConnections$DIP[j]))$sector[1]
          meanDataCount <- groupedConnections$meanDataCount[j]
          meanRDataCount <- groupedConnections$meanRDataCount[j]
          maxRCount <- groupedConnections$maxRCount[j]
          maxCount <- groupedConnections$maxCount[j]
          if (maxRCount > 0 || maxCount > 0) {
            circos.link(currentSector, chordRange, 1, chordRange, col="red", h.ratio=hRatio)
            if (meanRDataCount > 0) {
              circos.lines(x=xRange, y=c(meanRDataCount,meanRDataCount), sector.index=currentSector, col="#7B3294", lwd=5)
              # Decided not to add point to outside of sector, a red chord is indication enough
            }
            if (meanDataCount > 0) {
              circos.lines(x=xRange, y=c(meanDataCount,meanDataCount), sector.index=1, col="#7B3294", lwd=5)
              # Decided not to add point to outside of sector, a red chord is indication enough
            }
          } else {
            if (meanRDataCount > 0) {
              circos.link(currentSector, chordRange, 1, chordRange, col=linkColors[1], h.ratio=hRatio)
              circos.lines(x=xRange, y=c(meanRDataCount,meanRDataCount), sector.index=currentSector, col="#7B3294", lwd=5)
            } else {
              circos.link(currentSector, chordRange, 1, chordRange, col=linkColors[2], h.ratio=hRatio)
            }
            circos.lines(x=xRange, y=c(meanDataCount,meanDataCount), sector.index=1, col="#7B3294", lwd = 2)
          }
        }
      } else { # Draw chords for consecutive and same-colored sectors
        
        # Original dplyr call
        # groupedConnections <- connections %>% group_by(DIP) %>%
        #   summarize(meanRDataCount=mean(!!RdataColumn), meanDataCount=mean(!!dataColumn), maxRCount=sum(!!RdataColumn>=max), maxCount=sum(!!dataColumn>=max), .groups="keep") %>%
        #   arrange(meanRDataCount)

        # dplyr has slowed for summarizing on groups when there are many groups, while data.table is fast
        # Here we set number of threads to 1 so as to not affect other processes, convert 'connections' data.frame to 
        # data.table, utilize dtplyr pipes to manipulate data.table using same syntax as dplyr, and convert back
        # to data.frame. This improves performance by ~30x on certain data.
        setDTthreads(1)
        connectionsDT <- data.table(connections)
        groupedConnectionsDT <- connectionsDT %>% group_by(DIP) %>%
          summarize(meanRDataCount=mean(!!RdataColumn), meanDataCount=mean(!!dataColumn), maxRCount=sum(!!RdataColumn>=max), maxCount=sum(!!dataColumn>=max), .groups="keep") %>%
          arrange(meanRDataCount)
        groupedConnections <- as.data.frame(groupedConnectionsDT)

        # Creating three data frames -- one for no response from DIP, another for a reponse from DIP less than max,
        # and another for response from DIP greater or equal to max
        maxResponseDIPs <- groupedConnections %>% mutate(maxCombined=maxCount+maxRCount) %>%
          filter(maxCombined>0) %>% # DIPs that have values which exceed max
          arrange(maxCombined) %>%
          mutate(maxCombined=NULL)
        groupedConnections <- setdiff(groupedConnections,maxResponseDIPs)
        noResponseDIPs <- groupedConnections %>% filter(meanRDataCount==0) # Amber plotting
        groupedConnections <- setdiff(groupedConnections,noResponseDIPs)
        responseDIPs <- groupedConnections %>% arrange(meanRDataCount) # Renaming for clarity and sorting just in case

        noResponseTally <- nrow(noResponseDIPs)
        responseTally <- nrow(responseDIPs)
        maxTally <- nrow(maxResponseDIPs)

        # Draw three chords, one for each data frame. Amber-Teal-Red clockwise. For the Teal and Red sections,
        # plot y-values in the plotting section
        currentStartPosition <- 1
        if (noResponseTally != 0) {
          circos.link(2, c(currentStartPosition,currentStartPosition+noResponseTally-1), 1, 1, col=linkColors[2], h.ratio=hRatio) # Drawing chord
        }
        currentStartPosition <- currentStartPosition + noResponseTally
        if (responseTally != 0) {
          circos.link(2, c(currentStartPosition,currentStartPosition+responseTally-1), 1, 1, col=linkColors[1], h.ratio=hRatio) # Drawing chord
          # Creating two vectors to represent x and y values for points from the teal chord
          xPointsReduced <- vector(mode="numeric", length = floor(responseTally/4)) 
          yPointsReduced <- vector(mode="numeric", length = floor(responseTally/4))
          for (j in 1:length(xPointsReduced)) {
            xPointsReduced[j] <- (j*4)+currentStartPosition-1
            yPointsReduced[j] <- responseDIPs$meanRDataCount[j*4]
          }
          circos.lines(x=xPointsReduced, y=yPointsReduced, sector.index=2, col="#7B3294", lwd=6) # Drawing line
        }
        currentStartPosition <- currentStartPosition + responseTally
        if (maxTally != 0) {
          circos.link(2, c(currentStartPosition,currentStartPosition+maxTally-1), 1, 1, col="red", h.ratio=hRatio) # Drawing chord
          # Creating two vectors to represent x and y values for points from the red chord
          xPointsReduced <- vector(mode="numeric", length = floor(maxTally/4)) 
          yPointsReduced <- vector(mode="numeric", length = floor(maxTally/4))
          for (j in 1:length(xPointsReduced)) {
            xPointsReduced[j] <- (j*4)+currentStartPosition-1
            yPointsReduced[j] <- maxResponseDIPs$meanRDataCount[j*4]
          }
          circos.lines(x=xPointsReduced, y=yPointsReduced, sector.index=2, col="#7B3294", lwd=6) # Drawing line
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
          if (dipConnections[[dataColumn]][k] >= max || dipConnections[[RdataColumn]][k] >= max) {
            circos.points(x = dipConnections$TEND[k], y = dipConnections[[dataColumn]][k], sector.index=1, col="#7B3294", pch=19)
            if (dipConnections[[dataColumn]][k] >= max) {suppressMessages(circos.points(x = dipConnections$TEND[k], y = dataMax + uy(2, "mm"), sector.index=1, col="red", pch=19))}
            if (dipConnections[[RdataColumn]][k] != 0) {
              circos.points(x = dipConnections$TEND[k], y = dipConnections[[RdataColumn]][k], sector.index=currentSector, col="#7B3294", pch=19)
              if (dipConnections[[RdataColumn]][k] >= max) {suppressMessages(circos.points(x = dipConnections$TEND[k], y = dataMax + uy(2, "mm"), sector.index=currentSector, col="red", pch=19))}
            }
            circos.link(currentSector, dipConnections$TEND[k], 1, dipConnections$TEND[k], lwd=2, col="red", h.ratio=hRatio)
          } else {
            circos.points(x = dipConnections$TEND[k], y = dipConnections[[dataColumn]][k], sector.index=1, col="#7B3294", pch=19)
            if (dipConnections[[RdataColumn]][k] != 0) {
              circos.points(x = dipConnections$TEND[k], y = dipConnections[[RdataColumn]][k], sector.index=currentSector, col="#7B3294", pch=19)
              circos.link(currentSector, dipConnections$TEND[k], 1, dipConnections$TEND[k], col=linkColors[1], h.ratio=hRatio)
            } else {
              circos.link(currentSector, dipConnections$TEND[k], 1, dipConnections$TEND[k], col=linkColors[2], h.ratio=hRatio)
            }
          }
        }
      }
    }
    
    # Label sectors based on their destination IP's 
    if (dests) {
      # Found that adding labels to destination sectors when there are any more than 10 results in overlapping text
      if (destinationCount <= 10) {
        for (j in 1:nrow(connectionMapping)) {
          # Suppressing warning b/c we WANT the text of the destination IP to be printed outside of the plotting region
          suppressMessages(
            circos.text(x=xMiddle, y=dataMax+ uy(6, "mm"), sector.index=connectionMapping$sector[j], 
                        labels=maskIP(connectionMapping$DIP[j],mask), cex=1.75, niceFacing=TRUE, facing="bending"))
        }
      }
    }
    circos.clear()
    
    # Drawing boxes around the titles of the plots whose SIP's are from within the cluster's network
    if (!is.null(subnet)) {
      count <- str_count(subnet, pattern="\\.")
      splitIP <- strsplit(source, split="\\.")[[1]]
      subIP <- splitIP[1]
      if (count > 0) {
        for (j in 2:(count+1)) {
          subIP <- paste0(subIP, ".", splitIP[j])
        }
      }
      
      # Compare the source's IP with the subnet provided or found, draw rectangle around source
      # if it resides within the subnet
      if (strcmpi(subIP,subnet)) {
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
    }
    
    # Masking the title of the plot
    source <- maskIP(source,mask)
    
    # Setting the title for each individual plot
    if (strcmp(sortType,"cluster")) {
      cluster <- outliers$clusterCenter[i]
      modTitle <- paste0(source, " -- ", cluster)
      title(main=modTitle, line=-0.3)
    } else if (strcmp(sortType,"threat")) {
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
  circos.clear() # Clearing again, warnings are thrown occasionally 
  
  # Counting the total number of SIPs
  sourceCount <- nrow(outliers)
  # Specify rows and columns based on user option
  # bestDimensions function finds grid dimensions whose ratio is closest to 8.5/11
  dimensions <- bestDimensions(sourceCount)
  if (strcmp(orientation,"p")) {
    cols <- dimensions[1]
    rows <- dimensions[2]
  } else if (strcmp(orientation,"l")) {
    cols <- dimensions[2]
    rows <- dimensions[1]
  } else {
    modifiedDimensions <- FALSE
    if (dimensions[1] > 8) { # If there are more than 8 columns
      dimensions[1] <- 8
      dimensions[2] <- ceiling(sourceCount/8)
      modifiedDimensions <- TRUE
    }
    if (strcmp(orientation,"pe")) {
      cols <- dimensions[1]
      rows <- dimensions[2]
    } else {
      cols <- dimensions[2]
      rows <- dimensions[1]
    }
  }

  arrangedGrob <- arrangeGrob(grobs=plot.list, nrow=rows, ncol=cols, top=textGrob(as.character(banner), gp=gpar(fontsize=8)))
  #gtable_show_layout(arrangedGrob)
  
  # Drawing vertical lines between plots to demarcate clusters
  if (strcmp(sortType,"cluster")) {
    clusters <- outliers %>% group_by(clusterCenter) %>% tally() %>% arrange(desc(clusterCenter))
    iterations <- nrow(clusters)-1 # Only need to draw n-1 separators
    if (iterations > 0) {
      position <- 0
      for (i in 1:iterations) {
        position <- position + clusters$n[i]
        row <- as.integer(position/cols) + 2
        column <- position - ((row-2)*cols) + 1
        arrangedGrob <- gtable_add_grob(arrangedGrob, 
                                        grobs=segmentsGrob(x0 = 0, y0 = 0, x1 = 0, y1 = 1, gp=gpar(lwd=2)), 
                                        t = row, l = column, b = row, r = column, name=paste0("sep",i))
      }
    }
  }
  
  if (strcmp(orientation,"pe") || strcmp(orientation,"le")) {
    if (modifiedDimensions) {
      # Since we're allowing only 8 plots on the short side (which is close to the number of inches, 8.5),
      # we'll extend the long side (11 inches) by the factor that the number of plots is greater than 11.
      longSideFactor <- dimensions[2]/11
    } else {
      longSideFactor <- 1
    }
  }
  
  # Use ggsave to save all png's to single file, called fileCombined (specified on line 108)
  if (strcmp(orientation,"l")) { # drawing in landscape mode
    ggsave(path=filePath,filename=fileCombined, width=11, height=8.5, arrangedGrob, dpi=400) # Upping dpi from 300 to 400
  } else if (strcmp(orientation,"p")){ # Drawing in portrait mode
    ggsave(path=filePath,filename=fileCombined, width=8.5, height=11, arrangedGrob, dpi=400) # Upping dpi from 300 to 400
  } else if (strcmp(orientation,"le")) { # drawing in landscape extended
    ggsave(path=filePath,filename=fileCombined, width=11*longSideFactor, height=8.5, arrangedGrob, limitsize=FALSE)
  } else if (strcmp(orientation,"pe")) { # drawing in portrait extended
    ggsave(path=filePath,filename=fileCombined, width=8.5, height=11*longSideFactor, arrangedGrob, limitsize=FALSE)
  }
}

# If this was called as an Rscript from the command line, parse arguments
# This if-staement is similar to python's if __name__ == "__main__"
if (sys.nframe() == 0L) {
  # Variable declarations
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
  
  # Arguments list. Using package "optparse"
  option_list = list(
    make_option(c("-o", "--outlier-file"), type="character", default=NULL, 
                help="outliers file name (should include full path)", metavar="filename"),
    make_option(c("-t", "--type"), type="character", default="jpg", 
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
                help="maximum packet count for a link or sector, above which a red dot or line will be drawn outside the sector [default= %default]", metavar="integer"),
    make_option(c("-D", "--data-column"), type="character", default="packet",
                help="the data column in the 'links' file to use as the y-value in every sectors' plot {flow=FlowCount,byte=ByteCount,packet=PacketCount} [default= %default]", metavar="string"),
    make_option(c("-H", "--h-ratio"), type="double", default="0.7",
                help="a double between 0 and 1. closer to 0, the apex of a curved link drawn between two points passes nearer to the center of the circle plot [default= %default]", metavar="double")
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
    outlierFile <- opt$'outlier-file'
  }
  
  # Logic for file type
  if (strcmpi("png",opt$type)) {
    fileType <- "png"
  } else if (strcmpi("jpg",opt$type) || strcmpi("jpeg",opt$type)) {
    fileType <- "jpeg"
  } else if (strcmpi("pdf",opt$type)) {
    fileType <- "pdf"
  } else {
    stop("The file type must be one of the three: 'png', 'pdf', 'jpg', or 'jpeg'.")
  }
  
  # Logic for sorting type
  if (strcmpi(opt$sort,"ip")) {
    sortType <- "ip"
  } else if (strcmpi(opt$sort,"cluster")) {
    sortType <- "cluster"
  } else if (strcmpi(opt$sort,"threat")) {
    sortType <- "threat"
  } else {
    stop("The sort option must be one of the three: 'ip', 'cluster', or 'threat'.")
  }
  
  # Logic for aspect ratio
  if (strcmpi(opt$'aspect-ratio',"l")) {
    orientation <- "l"
  } else if (strcmpi(opt$'aspect-ratio',"p")) {
    orientation <- "p"
  } else if (strcmpi(opt$'aspect-ratio',"le")) {
    orientation <- "le"
  } else if (strcmpi(opt$'aspect-ratio',"pe")) {
    orientation <- "pe"
  } else {
    stop("Aspect ratio must be 'l' (landscape), 'p' (portrait), 'le' (landscape extended), or 'pe' (portrait extended).")
  }
  
  # Logic for fast
  if (opt$fast) {
    fast <- TRUE
  } else {
    fast <- FALSE
  }
  
  # Logic for mask
  if (strcmpi(opt$mask,"/0")) {
    mask <- "/0"
  } else if (strcmpi(opt$mask,"/8")) {
    mask <- "/8"
  } else if (strcmpi(opt$mask,"/16")) {
    mask <- "/16"
  } else if (strcmpi(opt$mask,"/24")) {
    mask <- "/24"
  } else if (strcmpi(opt$mask,"/32")) {
    mask <- "/32"
  } else {
    stop("Masking must be set to one of the four: '/0', '/8', '/16', '/24', or '/32'.")
  }
  
  # Logic for name
  if (is.null(opt$name)) {
    name <- NULL
  } else {
    name <- opt$n
  }
  
  # Logic for dests
  if (opt$dests) {
    dests <- TRUE
  } else {
    dests <- FALSE
  }
  
  # Logic for cores
  if (is.null(opt$cores)) {
    ncpCoreCount <- detectCores()-2
  } else if (is.integer(opt$cores)){
    if (opt$cores > detectCores()) {
      ncpCoreCount <- detectCores()
    } else if (opt$cores < 1){
      ncpCoreCount <- 1
    } else {
      ncpCoreCount <- opt$cores
    }
  } else {
    stop("The number of cores must be an integer.")
  }
  
  # Logic for max data
  if (is.null(opt$'max-data')) {
    maxData <- NULL
  } else if (is.integer(opt$'max-data')){
    maxData <- opt$'max-data'
  } else {
    stop("The maximum must be an integer value.")
  }
  
  # Logic for banner
  if (is.null(opt$banner)) {
    banner <- NULL
  } else {
    banner <- opt$banner
  }
  
  # Logic for subnet
  if (is.null(opt$subnet)) {
    subnet <- NULL
  } else {
    subnet <- opt$subnet
  }
  
  # Logic for data column
  if (strcmpi(opt$'data-column', "packet")) {
    dataColumn <- "packet"
  } else if (strcmpi(opt$'data-column', "byte")){
    dataColumn <- "byte"
  } else if (strcmpi(opt$'data-column', "flow")) {
    dataColumn <- "flow"
  } else {
    stop("The data column must be set to one of the three:'packet', 'byte', or 'flow'.")
  }
  
  # Logic for h-ratio
  if (is.null(opt$'h-ratio')) {
    hRatio <- 0.7
  } else {
    if (opt$'h-ratio' > 1) {
      hRatio <- 0.9
    } else if (opt$'h-ratio' < 0) {
      hRatio <- 0.1
    } else {
      hRatio <- opt$'h-ratio'
    }
  }
  
  # Print command line argument values
  argNames <- c("outlier-file","type","sort","fast","mask","dests","aspect-ratio","banner","subnet","cores","max-data","data-column","h-ratio")
  collectedArgs <- list(outlierFile, fileType, sortType, fast, mask, dests, orientation, banner, subnet, ncpCoreCount, maxData, dataColumn, hRatio)
  for (i in 1:length(argNames)) {
    cat(paste0(argNames[i],": '",collectedArgs[i],"'\n"))
  }
  
  # Set number of cores to argument
  changeCoreCount(ncpCoreCount) # Changing core count based on user's request
  # Call makeCirclesFromFile with the arguments, and when completed, print the time it took to run
  tic()
  makeCirclesFromFile(outlierFile, name=name, fileType=fileType, sortType=sortType, fast=fast, mask=mask, dests=dests, orientation=orientation, banner=banner, subnet=subnet, max=maxData, dataColumn=dataColumn, hRatio=hRatio)
  toc()
}