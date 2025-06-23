#!/bin/bash

cd log/client/
    echo "rm all client logs"
    rm *.txt
    cd ../..

cd log/server/
    echo "rm all server logs"
    rm *.txt
    cd ../..