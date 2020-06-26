library(doSNOW)

cl <- makeCluster(2)
registerDoSNOW(cl)
#foreach(i=1:3) %dopar% sqrt(i)
closeCluster(cl)
show("Successfully closed the cluster")