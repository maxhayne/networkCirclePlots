if (!suppressMessages(require("pacman"))) install.packages("pacman")
pacman::p_load("pracma","doParallel","circlize","dplyr","bitops", "tictoc",
               "tools","anytime","grid","png","ggplot2","gridExtra","stringr",
               "vroom","gtable")