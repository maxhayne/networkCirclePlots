library(shiny)
library(pracma)
library(stringr)
library(shinyWidgets)

dirs <- list.dirs(path="www", full.names=FALSE, recursive=FALSE)

ui <- fluidPage(
  sidebarLayout(
    sidebarPanel(
      titlePanel("Network Circle Plots"),
      htmlOutput("date_selector"),
      htmlOutput("subnet_selector"),
      htmlOutput("minute_selector")
    ),
    mainPanel(
      uiOutput(outputId = "image")
    ),
    position=c("left","right")
  )
)

server <- function(input, output) {
  output$date_selector <- renderUI({
    selectInput(inputId = "date", label = "Date:", choices = dirs)
  })
  
  output$subnet_selector <- renderUI({
    sublist <- c()
    imgs <- list.files(path=paste0("www/",input$date,"/"), pattern=".png", full.names=FALSE)
    tmp <- "tmp"
    for (i in 1:length(imgs)) {
      if (str_count(imgs[i], "_") > 1) {
        sub <- strsplit(imgs[i],"_")[[1]][2]
        if (!(sub %in% sublist)) {
          sublist <- c(sublist,sub)
        }
      } else {
        if (!("None" %in% sublist)) {
          sublist <- c("None", sublist)
        }
      }
    }
    selectInput(inputId = "subnet", label = "SubNet:", choices = sublist)
  })
  
  output$minute_selector <- renderUI({
    currentSubNet <- input$subnet
    counter <- 0
    imgs <- list.files(path=paste0("www/",input$date,"/"), pattern=".png", full.names=TRUE)
    if (strcmp("None",currentSubNet)) {
      for (i in 1:length(imgs)) {
        if (str_count(imgs[i], "_") == 1) {
          counter <- counter+1
        }
      }
    } else {
      for (i in 1:length(imgs)) {
        if (strcmpi(strsplit(imgs[i],"_")[[1]][2],currentSubNet)) {
          counter <- counter+1
        }
      }
    }
    slider_choices <- vector(mode="character",length=counter)
    index <- 1
    if (strcmp("None",currentSubNet)) {
      for (i in 1:length(imgs)) {
        if (str_count(imgs[i], "_") == 1) {
          slider_choices[index] <- strsplit(basename(imgs[i]),"_")[[1]][1]
          index <- index+1
        }
      }
    }
    else {
      for (i in 1:length(imgs)) {
        tmpSubNet <- strsplit(imgs[i],"_")[[1]][2]
        if (strcmpi(tmpSubNet,currentSubNet)) {
          slider_choices[index] <- strsplit(basename(imgs[i]),"_")[[1]][1]
          index <- index+1
        }
      }
    }
    shinyWidgets::sliderTextInput(inputId = "minute", label = "Epoch Minute:", choices=slider_choices,
                                  animate = animationOptions(interval = 600, loop = TRUE))
  })
  
  output$image <- renderUI({
    if (strcmp(input$subnet,"None")) {
      img(src=paste0(input$date,"/", input$minute, "_outliers.png"), height="80%", width="80%")
    } else {
      img(src=paste0(input$date,"/", input$minute, "_", input$subnet, "_outliers.png"), height="100%", width="100%")
    }
  })
}

shinyApp(ui = ui, server = server)