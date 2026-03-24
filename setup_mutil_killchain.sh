#!/usr/bin/env bash

networkname="ctfnet"
network_exists=$(docker network ls | grep $networkname)
# Create network
if [ -z "$network_exists" ]; then
    docker network create ctfnet
else
    echo "Network ${networkname} already exists, skip!"
fi

BASE=$(dirname $0)
# Build main docker image
cd $BASE/docker/mutil_killchain && docker build --platform linux/amd64 --build-arg HOST_UID=$(id -u) -t ctfenv:mutil-killchain .

cd -
echo "Installing python package"
pip install --editable .
