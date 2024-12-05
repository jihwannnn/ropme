#!/bin/bash
PORT=31337
EXEC_NAME=ropme 
socat -v tcp-listen:$PORT,fork,reuseaddr EXEC:./$EXEC_NAME

