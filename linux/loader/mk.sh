#!/bin/sh

gcc -o loader.so -shared -Wall -W -pedantic -Wno-unused-function -Wno-variadic-macros -Wno-missing-field-initializers -O2 -I. -Irune -fPIC -Wl,-init=initme -Wl,-fini=finime -s -DXSYMBOL=ZYA -DXSYMBOL_SIZE=0x90 loader.c cxa.c rune/mac.c -ldl
