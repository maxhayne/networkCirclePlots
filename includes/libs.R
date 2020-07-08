packages = c("optparse","pracma","doParallel","tictoc","circlize","dplyr","bitops",
             "tools","anytime","foreach","grid","png","ggplot2","gridExtra","stringr",
             "vroom","gtable")

# If any packages are not installed, install them, otherwise, load them silently
package.check <- lapply(
  packages,
  FUN = function(x) {
    if (!suppressMessages(require(x, character.only = TRUE))) {
      install.packages(x, dependencies = TRUE)
      library(x, character.only = TRUE)
    }
  }
)