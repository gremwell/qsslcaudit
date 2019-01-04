#!/bin/sh -xe
docker build -t qs-unsafe-bionic -f Dockerfile.qs-unsafe-bionic .
docker run --name qs-unsafe-bionic --rm -it qs-unsafe-bionic
