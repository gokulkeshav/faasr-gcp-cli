#!/usr/local/bin/Rscript

#' @title Set an entrypoin / Source R codes - for GCP
#' @description When the docker containers run, they start this R code very first time.
#'              This is necessary because it sets library("FaaSr") so that users code can use the FaaSr library and
#'              user's functions would be downloaded from the user's github repository and then they are sourced by
#'              this function. 
#' @param JSON payload is passed as an input when the docker container starts.

setwd("./action")
if (!requireNamespace("devtools", quietly = TRUE)) {
  install.packages("devtools")
}
devtools::install_github("gokulkeshav/FaaSr-package")

if (!require("openssl", quietly = TRUE)) {
  install.packages("openssl")
}

# Once the package is confirmed to be installed, load it into the current R session.
library(openssl)

library("jsonlite")
library("httr")
library("FaaSr")
source("faasr_start_invoke_helper.R")

# get the single, base64-encoded JSON string from the CLI
args <- commandArgs(TRUE)
b64_payload <- args[1]

# decode it back into raw JSON and parse into an R list
.faasr   <- rawToChar(openssl::base64_decode(b64_payload))

# now start FaaSr as before
.faasr <- FaaSr::faasr_start(.faasr)
if (.faasr[1] == "abort-on-multiple-invocation") {
  q("no")
}

# Download the dependencies
funcname <- .faasr$FunctionList[[.faasr$FunctionInvoke]]$FunctionName
faasr_dependency_install(.faasr, funcname)

# Execute User function
FaaSr::faasr_run_user_function(.faasr)

# Trigger the next functions
FaaSr::faasr_trigger(.faasr)

# Leave logs
msg_1 <- paste0('{\"faasr\":\"Finished execution of User Function ',.faasr$FunctionInvoke,'\"}', "\n")
cat(msg_1)
result <- faasr_log(msg_1)
msg_2 <- paste0('{\"faasr\":\"With Action Invocation ID is ',.faasr$InvocationID,'\"}', "\n")
cat(msg_2)
result <- faasr_log(msg_2)
