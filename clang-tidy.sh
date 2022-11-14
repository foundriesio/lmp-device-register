#!/bin/sh -ex

cd $(dirname $(readlink -f $0))

clang-tidy-6.0 ./src/main.cpp -- $(pkg-config --cflags glib-2.0) -DDEVICE_API='"url"' -DDOCKER_COMPOSE_APP="1" -DHARDWARE_ID='"foo"' -DGIT_COMMIT='"deadbeef"'
