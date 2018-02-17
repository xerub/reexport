#!/usr/bin/python

import os
import sys

def O(cmd):
    return os.popen(cmd).read().splitlines()

def U(file, where):
    if os.uname()[0] == 'Linux':
        return O("ldd -r '%s' | awk '/undefined symbol/{print $3}'" % file)
    else:
        return O("nm -m -undefined-only '%s' | awk '/\(undefined.*%s\)/{print $3}' | sort" % (file, where))

def E(files):
    if os.uname()[0] == 'Linux':
        return O("nm -D --defined-only '%s' | awk '{print $3}' | sort -u" % "' '".join(files))
    else:
        return O("nm -defined-only '%s' | awk '{print $3}' | sort -u" % "' '".join(files))

def X(xlat):
    # file format is: mangled = symbol
    return O("awk '{print $3}' '%s'" % xlat)
    #with open(xlat) as f:
    #    return f.read().splitlines()

if len(sys.argv) < 3:
    print "usage: %s binary xlat.txt lib [lib...]" % sys.argv[0]
    exit(1)

u = U(sys.argv[1], sys.argv[3].split('.')[0])
x = X(sys.argv[2])
e = E(sys.argv[3:])

for i in u:
    if not i in e and not i in x:
        print i
