#!/bin/bash

# Get ct-monitor top level using git
CT_MONITOR_BASE_DIR=`git rev-parse --show-toplevel`

# Go into ct-monitor dir and create binary for server.go
cd "$CT_MONITOR_BASE_DIR/ct-monitor"

# Remove previous binary if exists
rm server

# Create binary
go build server.go

# Go back to top level of the ct-monitor directory and run the server
cd "$CT_MONITOR_BASE_DIR"
ct-monitor/server -logtostderr=true