#!/bin/sh -ex

cd $(dirname $(readlink -f $0))

clang-tidy-6.0 ./src/main.cpp -- $(pkg-config --cflags glib-2.0) -DDEVICE_FACTORY='"foo"' -DDEVICE_API='"url"' -DDOCKER_APPS="1" -DAKLITE_TAGS="1" -DHARDWARE_ID='"foo"' -DGIT_COMMIT='"deadbeef"'
