#!/bin/sh

OLD=a
NEW=b

gcc -o lib$OLD.dylib -shared -Wall -W -pedantic -O2 -Wl,-install_name,@executable_path/lib$OLD.dylib alpha.c

gcc -o lib$NEW.dylib -shared -Wall -W -pedantic -O2 -Wl,-install_name,@executable_path/lib$NEW.dylib -Wl,-reexport_library,lib$OLD.dylib -Wl,-alias_list,alias.txt beta.c

gcc -o testb -Wall -W -pedantic -O2 -L. testb.c -l$NEW
