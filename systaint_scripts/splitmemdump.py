#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Fri Feb  9 15:59:26 2018

@author: vigliag
"""
import os
import sys
inputfname = sys.argv[1]
reqaddr = 0
if len(sys.argv) > 2:
    reqaddr = int(sys.argv[2],16)
    
print "will look for {}".format(reqaddr)

indexfile = inputfname + ".idx"

try:
    os.mkdir("sections")
except:
    pass
#%%
with open(inputfname) as inputfile:
    with open(indexfile) as index:
        print(index.readline())
        print(index.readline())
        for line in index.readlines():
            print line
            offs, length, start = line.split()   
            offs = int(offs, 16)
            length = int(length, 16)
            if (reqaddr 
                and reqaddr >= start
                and reqaddr < start + length):
                
                inputfile.seek(offs)
                buff = inputfile.read(length)
                fname = "mem.{}.dump".format(start)
                with open(fname, "w") as outf:
                    outf.write(buff)
                print "found"
                break
            
            else:
                inputfile.seek(offs)
                buff = inputfile.read(length)
                fname = "mem.{}.dump".format(start)
                with open("sections/" + fname, "w") as outf:
                    outf.write(buff)