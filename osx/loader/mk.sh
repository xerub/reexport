#!/bin/sh

gcc -o loader.dylib -shared -Wall -W -pedantic -Wno-unused-parameter -Wno-variadic-macros -O2 -I. -Igelfload -L. -DXSYMBOL=ZYA -DXSYMBOL_SIZE=0x90 main.c gnuh.c cxa.c gelfload/elfload.c gelfload/dlfcn.c gelfload/bbuffer.c -ldl
