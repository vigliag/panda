#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Mon Feb 19 23:33:24 2018

@author: vigliag
"""

#%%
import json

with open("asidstory") as f:
    asidstory = f.readlines()
    
a = []
for i in asidstory[2:]:
    i = i.strip()
    if not i:
        break
    count, pid, name, asid, first, _, last = i.split()
    a.append({"count": int(count), "asid": int(asid,16), "pid": int(pid), "first_instruction": int(first), "last_instruction": int(last) - 1000000, "name": name})
    
with open("pids2.txt", "w") as f:
    for i in a:
        f.write(json.dumps(i) + "\n")
    
