#!/bin/sh

# this is the original library
gcc -o liba.so -shared -Wall -W -pedantic -O2 -fPIC -L. alpha.c

# create a full library (symbols from A & their aliases) for the sole purpose of linking main
gcc -o libb.so -shared -Wall -W -pedantic -O2 -fPIC both.c

# build main with both symbols (notice nocopyreloc)
gcc -o testb -Wall -W -pedantic -O2 -L. -fPIC -Wl,-z,nocopyreloc -Wl,-z,origin -Wl,-rpath,'$ORIGIN' testb.c -lb

# rebuild B so that it has COPY relocs for symbols imported from A (also define needed aliases)
gcc -o libb.so -shared -Wall -W -pedantic -O2 -L. -fPIE -pie -Wl,-E -Wl,--defsym=y=x beta.c -la -ldl
