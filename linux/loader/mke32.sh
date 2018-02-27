#!/bin/sh

gcc -o loader -m32 -Wall -W -pedantic -Wno-unused-function -Wno-variadic-macros -Wno-missing-field-initializers -O2 -I. -Irune -DXSYMBOL=ZYA -DXSYMBOL_SIZE=0x90 -DHAVE_MAIN loader.c cxa.c rune/mac.c -ldl
