#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
Created on Mon Nov 27 14:37:31 2017
@author: vigliag
"""

from collections import defaultdict
import json
import math
from copy import copy
import os


class CallDB(object):
    def __init__(self):
        self.idb = dict()
        self.name_addr = defaultdict(set)

    def load(self, filename):
        for line in open(filename):
            a,b,c,d = line.split(",")
            addr = int(a, 16)
            name = b.strip()
            self.idb[addr] = {"addr": addr, "name": b.strip(), "module": c.strip(), "offset": int(d)}
            self.name_addr[name].add(addr)

    def getAddr(self, name, default=None):
        return self.name_addr.get(name, default)

    def getName(self, addr, default=None):
        return self.idb.get(addr, default)
    
    def firstExt(self, entrypoints):
        for ep in entrypoints:
            f = self.getName(ep)
            if not f: continue
            for i in f:
                if f["name"] not in ["BaseThreadInitThunk", "KiFastSystemCall", "ZwContinue"]:
                    return f["name"]


class CallNode:
    uniqidctr = 0
    
    @classmethod
    def getID(cls):
        cls.uniqidctr += 1
        return cls.uniqidctr    
    
    def __init__(self):
        self.parent = None
        self.uniqid = self.getID()
        self.children = defaultdict(CallNode) # entrypoint to children map
        self.ids = set()
        self.totalblocks = 0
        self.maxblocks = 0
        self.distinctblocks = 0
        self.reads = []
        self.writes = []
        self.pc = 0
        self.subtree_depth = 0
        self.arith_instructions = 0
        self.total_instructions = 0
                
    def addChild(self, childcall):
        child_ep = childcall["pc"]
        self.children[child_ep].parent = self
        self.children[child_ep].mergeSiblingCall(childcall)
        return self.children[child_ep]
    
    def mergeSiblingCall(self, call):
        call_id = call["id"]
        self.pc = call["pc"]
        self.distinctblocks = max(self.distinctblocks, call["distinct_blocks"])
        self.totalblocks += call["sumexecs"]
        self.maxblocks = max(self.maxblocks, call["maxexecs"])        
        self.ids.add(call_id)
        self.reads += call["reads"]
        self.writes += call["writes"]
        self.arith_instructions = call["insn_arith"]
        self.total_instructions = call["insn_total"]
        
    def mergeNode(self, other):
        if self == other:
            return
        
        self.pc = other.pc
        self.distinctblocks = max(self.distinctblocks, other.distinctblocks)
        self.totalblocks = max(self.totalblocks, other.totalblocks)
        self.maxblocks = max(self.maxblocks, other.maxblocks)        
        self.ids += other.ids
        self.reads += other.reads
        self.writes += other.writes
        
    def collectChildren(self):
        children = copy(self.children)
        for child in self.children.values():
            children.update(child.collectChildren())
        return children
        


""" Build the treee """
class CallTree():
    def __init__(self):
        self.callid_callnode = {}
        self.ep_callid = defaultdict(set)
        self.ep_callnodes = defaultdict(set)
        self.roots = []
        self.fakeRoot = CallNode()
        self.callerPCs = defaultdict(set) #from pc to set of caller pcs

    def addCall(self, call):
        call_id = call["id"]
        parent_id = call["called_by"]

        if call["callstack"]:
            self.callerPCs[call["pc"]].add(call["callstack"][0])

        self.ep_callid[call["pc"]].add(call_id)
        
        if parent_id is None or parent_id not in self.callid_callnode:
            node = CallNode()
            node.mergeSiblingCall(call)
            self.roots.append(node)
            self.fakeRoot.children[node.pc] = node
            
        else:
            parent = self.callid_callnode[parent_id]
            node = parent.addChild(call)
            
        self.callid_callnode[call_id] = node
        self.ep_callnodes[node.pc].add(node)
        
    def addCalls(self, calls):
        for call in reversed(calls):
            self.addCall(call)
            
    def assignSubtreeDepths(self):
        def assignSubtreeDepthFromNode(callNode):    
            subtree_depth = 0
            
            for childpc, child in callNode.children.iteritems():
                child_depth = assignSubtreeDepthFromNode(child)
                subtree_depth = max(child_depth, subtree_depth)
            
            callNode.subtree_depth = subtree_depth        
            return subtree_depth + 1   
        
        assignSubtreeDepthFromNode(self.fakeRoot)



class TreeAnalyzer():
    def __init__(self, callTree):
        self.MAX_SUBTREE_DEPTH = 3
        self.MIN_ENTROPY = 0.92
        self.MAX_STRIKES = 3
        self.pc_yes = defaultdict(int)
        self.pc_nos = defaultdict(int)
        self.callTree = callTree

    def features(self, node):
        feats = {
            "has_complex_loops" : node.maxblocks > node.distinctblocks,
            "writes_high_entropy_data" : False,
            "reads_high_entropy_data" : False,
            "writes_strings" : False,
            "ratio_of_arith_instructions": 0,
            "total_instructions": node.total_instructions,
            "transforms_ascii_data": False
        }
    
        def asciiratio(acc):
            if acc["nulls"] >= acc["len"] * 0.8:
                return 0 #exclude null strings
            return float(acc["printableChars"] + acc["nulls"]) / acc["len"]
    
        #obfuscation heuristic
        #we consider two buffers to allow for xor obfuscation with a one-time-pad
        MINASCIIBUFFERSIZE = 20
        one_of_largest_read_buffer_is_ascii = False
        len_of_largest_read_ascii_buffer = 0
        largest_read_size = 0
        for read in sorted(node.reads, key=lambda a: a["len"])[-2:]:
            largest_read_size = read["len"]
            if read["len"] > MINASCIIBUFFERSIZE and asciiratio(read) > 0.8:
                one_of_largest_read_buffer_is_ascii = True
                len_of_largest_read_ascii_buffer = read["len"]
        
        one_of_largest_written_buffer_is_ascii = False
        len_of_largest_ascii_written_buffer = 0
        largest_write_size = 0
        writes_by_size = sorted(node.writes, key=lambda a: a["len"])[-2:]
        for write in writes_by_size:
            largest_write_size = write["len"]
            if write["len"] > MINASCIIBUFFERSIZE and asciiratio(write) > 0.8:
                one_of_largest_written_buffer_is_ascii = True
                len_of_largest_ascii_written_buffer = write["len"]
    
        #obfuscation
        if (one_of_largest_read_buffer_is_ascii 
            and not one_of_largest_written_buffer_is_ascii
            and largest_write_size >= len_of_largest_read_ascii_buffer):
            feats["transforms_ascii_data"] = True
        
        #deobfuscation
        if (one_of_largest_written_buffer_is_ascii
           and not one_of_largest_read_buffer_is_ascii
           and largest_read_size >= len_of_largest_ascii_written_buffer):
            feats["transforms_ascii_data"] = True
        
    
        if node.total_instructions:
            feats["ratio_of_arith_instructions"] = float(node.arith_instructions) / node.total_instructions

        for write in node.writes:
            if write["len"] > 15:
                entropy = (float(write["entropy"]) / math.log(write["len"], 2))

                if entropy > self.MIN_ENTROPY:
                    feats["writes_high_entropy_data"] = True

                if asciiratio(write) > 0.8:
                    feats["writes_strings"] = True
                    
        for read in node.reads:
            if read["len"] > 15:
                entropy = (float(read["entropy"]) / math.log(read["len"], 2))
                if entropy > self.MIN_ENTROPY:
                    feats["reads_high_entropy_data"] = True
                    break

        return feats

    def analyze(self, node):
        fts = self.features(node)
        return ((fts["writes_high_entropy_data"] or fts["reads_high_entropy_data"] or fts["transforms_ascii_data"]) and fts["total_instructions"] > 30 and
                node.subtree_depth < self.MAX_SUBTREE_DEPTH)

    def computePCScore(self,callNode):
        for childpc, child in callNode.children.iteritems():
            self.computePCScore(child)
            
        if self.analyze(callNode):
            self.pc_yes[callNode.pc] += 1
        else:
            self.pc_nos[callNode.pc] += 1
    
    def maybePromote(self, pc):
        callers = self.callTree.callerPCs.get(pc, set())
        
        # compute the maxSubTreeDepth, take maximum among all parents
        parentCallNodes = set()
        for caller in callers:
            parentCallNodes.update(self.callTree.ep_callnodes[caller])
        
        maxSubTreeDepth = 0
        for parentCallNode in parentCallNodes:
            maxSubTreeDepth = max(parentCallNode.subtree_depth, maxSubTreeDepth)
            
        if (len(parentCallNodes) == 0 or maxSubTreeDepth > 4
            or len(callers) != 1):
            return None

        caller = next(iter(callers))                
        
        #print "Promoting {} -> {}".format(hex(pc), hex(caller))
        return caller    
        
    
    def choosePrimitives(self):
        chosenPCs = set()
        for pc, yes in self.pc_yes.iteritems():
            nos = self.pc_nos[pc]
            if yes < nos or nos > self.MAX_STRIKES:
                continue
            
            callers = self.callTree.callerPCs.get(pc, set())
            
            #discard if we have no info about the caller
            if len(callers) == 0:
                continue
            
            if len(callers) > 5:
                continue
            
            chosenPCs.add(pc)
        
        return chosenPCs
    
    def runPromotions(self, chosenSet):
        #run promotion three times
        workingSet = copy(chosenSet)

        for j in range(5):
            for i in copy(workingSet):
                promoted_caller = self.maybePromote(i)
                if promoted_caller:
                    workingSet.remove(i)
                    workingSet.add(promoted_caller)

        for j in range(5):
            for i in copy(workingSet):
                callers = self.callTree.callerPCs.get(i, set())
                if callers & workingSet:
                    #print "removing other children", i
                    workingSet.remove(i)

        return workingSet

def high_arith_ratio(calls):
    for call in calls:
        arith = call["insn_arith"]
        total = call["insn_total"]
        total -= call.get("insn_movs", 0)
        
        if total > 0:
            ratio = float(arith) / total
        else:
            ratio = 0
            
        if total > 20 and ratio > 0.55:
            yield call, ratio


def parseCallsFromFile(functions_file='fn_memlogger'):
    parsedCalls = []
    with open(functions_file) as f:
        for line in f:
            parsedCalls.append(json.loads(line))

    parsedCalls = filter(lambda x: x['called_by'] != 0, parsedCalls)
    return parsedCalls

def analyzeCalls(parsedCalls):
    callTree = CallTree()
    callTree.addCalls(parsedCalls)
    callTree.assignSubtreeDepths()

    ta = TreeAnalyzer(callTree)
    ta.computePCScore(callTree.fakeRoot)
    primitives = ta.choosePrimitives()
    chosenfunctions = ta.runPromotions(primitives)

    #print "_".join(hex(pc) for pc in chosenfunctions)
    print len(chosenfunctions)
    return chosenfunctions


knownEncodingFunctionsList = """
CryptAcquireContextA
CryptAcquireContextW
CryptProtectData
CryptUnprotectData
CryptProtectMemory
CryptUnprotectMemory
CryptDecrypt
CryptEncrypt
CryptHashData
CryptDecodeMessage
CryptDecryptMessage
CryptEncryptMessage
CryptHashMessage
CryptExportKey
CryptGenKey
CryptCreateHash
CryptDecodeObjectEx
Ssl3GenerateKeyMaterial
EncryptMessage
DecryptMessage
MultiByteToWideChar
WideCharToMultiByte
_snprintf
DnsValidateName_W
CPVerifySignature
CPGetHashParam
RtlDecompressBuffer
SealMessage
UnsealMessage
CryptHashCertificate2
CPHashData
CPGenRandom
CPEncrypt
UuidCreate
BCryptDecrypt
BCryptEncrypt
""".split()
knownEncodingFunctionsList = filter(None,knownEncodingFunctionsList)


def filterPrivate(mmaps, pid, functions):
    res = set()
    for i in functions:
        region = mmaps.get_region_str(pid, i)
        if "private" in region:
            res.add(i)
    return res