#!/bin/sh

gcc -o loader -Wall -W -pedantic -Wno-unused-parameter -Wno-variadic-macros -O2 -I. -Igelfload -DXSYMBOL_SIZE=1 -DHAVE_MAIN main.c gnuh.c cxa.c gelfload/elfload.c gelfload/dlfcn.c gelfload/bbuffer.c -ldl
