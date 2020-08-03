library(shiny)
library(pracma)
library(shinyWidgets)

# USER SHOULD SET THESE
#######################
date <- "2020-05-21"
subnet <- "132" # Set the subnet we want to check
#######################

counter <- 0
imgs <- list.files(path=paste0("www/",date), pattern=".png", full.names=TRUE)
for (i in 1:length(imgs)) {
  if (strcmpi(strsplit(imgs[i],"_")[[1]][2],subnet)) {
    counter <- counter+1
  }
}
selected_imgs <- vector(mode="character",length=counter)
index <- 1
for (i in 1:length(imgs)) {
  tmpSubNet <- strsplit(imgs[i],"_")[[1]][2]
  if (strcmpi(tmpSubNet,subnet)) {
    selected_imgs[index] <- imgs[i]
    index <- index+1
  }
}
slider_choices <- vector(mode="character",length=counter)
for (i in 1:length(selected_imgs)) {
  slider_choices[i] <- strsplit(basename(selected_imgs[i]),"_")[[1]][1]
}
#print(slider_choices)

ui <- fluidPage(
  sidebarLayout(
    sidebarPanel(
      titlePanel("Network Circle Plots"),
      shinyWidgets::sliderTextInput(inputId = "slider", label = "Epoch Minute:", choices=slider_choices,
                      animate = animationOptions(interval = 450, loop = TRUE))
    ),
    mainPanel(
      #images to display
      lapply(X = slider_choices, FUN = function(i) {
        #print(paste0(paste0(date,"/plots/", i, "_", subnet, "_outliers.png")))
        # condition on the slider value
        conditionalPanel(condition = paste0("input.slider == ", i),
                         # img(src=paste0("/data/netbrane/outliers/2020-05-21/plots/", j, "_132_outliers.png"))
                         # img(src = paste0("https://raw.githubusercontent.com/pvictor/images/master/",
                         #                  sprintf("%04d", i), "plot.png"))
                         img(src=paste0(date,"/", i, "_", subnet, "_outliers.png"), height="68%", width="68%")

        )
      })
    ),
    position=c("left","right")
  )
)

server <- function(input, output) {
}

shinyApp(ui = ui, server = server)