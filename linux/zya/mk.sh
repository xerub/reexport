#!/bin/sh

OLD=a
MID=2
NEW=b

gcc -o lib$MID.so -shared -Wall -W -pedantic -Wno-variadic-macros -O2 -L. -fPIC -s lib/lib.c lib/misc.c lib/todo.c -l$OLD

# rebuild 'new' so that it has COPY relocs for symbols imported from 'old' (also define needed aliases)
gcc -o lib$NEW.so -shared -Wall -W -pedantic -O2 -L. -fPIE -pie -Wl,-E -nostdlib \
-Wl,--defsym=ash=zya45 \
-Wl,--defsym=batch=zya60 \
-Wl,--defsym=callui=zya99 \
-Wl,--defsym=dbg=zya144 \
-Wl,--defsym=errorexit=zya224 \
-Wl,--defsym=inf=zya597 \
-Wl,--defsym=lnar_size=zya679 \
-Wl,--defsym=ph=zya787 \
-Wl,--defsym=root_node=zya935 \
-Wl,--defsym=under_debugger=zya1094 \
-s beta.c -l$MID -l$OLD -ldl -lc
