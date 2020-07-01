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
    imgs <- list.files(path=paste0("www/",input$date,"/plots"), pattern=".png", full.names=FALSE)
    tmp <- "tmp"
    for (i in 1:length(imgs)) {
      if (str_count(imgs[i], "_") > 1) {
        sub <- strsplit(imgs[i],"_")[[1]][2]
        if (!(sub %in% sublist)) {
          sublist <- c(sublist,sub)
        }
      }
    }
    selectInput(inputId = "subnet", label = "SubNet:", choices = sublist)
  })
  
  output$minute_selector <- renderUI({
    currentSubNet <- input$subnet
    counter <- 0
    imgs <- list.files(path=paste0("www/",input$date,"/plots"), pattern=".png", full.names=TRUE)
    for (i in 1:length(imgs)) {
      if (strcmpi(strsplit(imgs[i],"_")[[1]][2],currentSubNet)) {
        counter <- counter+1
      }
    }
    selected_imgs <- vector(mode="character",length=counter)
    index <- 1
    for (i in 1:length(imgs)) {
      tmpSubNet <- strsplit(imgs[i],"_")[[1]][2]
      if (strcmpi(tmpSubNet,currentSubNet)) {
        selected_imgs[index] <- imgs[i]
        index <- index+1
      }
    }
    slider_choices <- vector(mode="character",length=counter)
    for (i in 1:length(selected_imgs)) {
      slider_choices[i] <- strsplit(basename(selected_imgs[i]),"_")[[1]][1]
    }
    shinyWidgets::sliderTextInput(inputId = "minute", label = "Epoch Minute:", choices=slider_choices,
                                  animate = animationOptions(interval = 600, loop = TRUE))
  })
  
  output$image <- renderUI({
    img(src=paste0(input$date,"/plots/", input$minute, "_", input$subnet, "_outliers.png"), height="68%", width="68%")
  })
}

shinyApp(ui = ui, server = server)