#!/bin/sh -xe
docker build -t qs-safe-xenial -f Dockerfile.qs-safe-xenial .
docker run --name qs-safe-xenial --rm -it qs-safe-xenial
