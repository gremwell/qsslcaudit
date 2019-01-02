#!/bin/sh

find build/ -executable -type f -name tests_SslTest\* | xargs -n 1 sh -c
