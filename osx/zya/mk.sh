#!/bin/sh

OLD=a
NEW=b

gcc -o lib$NEW.dylib -shared -Wall -W -pedantic -O2 -Wl,-install_name,@executable_path/lib$NEW.dylib -Wl,-reexport_library,lib$OLD.dylib -Wl,-alias_list,alias.txt -Wl,-current_version,1.0.0 -Wl,-compatibility_version,1.0.0 beta.c
