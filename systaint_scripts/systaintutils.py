import glob
import json
from bisect import bisect_left
from collections import defaultdict
import os
import shelve

class MemoryMaps:
    def __init__(self):
        self.mmaps = defaultdict(dict)

    def from_files(self, folder="."):
        for file in glob.glob("/".join([folder,"processInfo*.json"])):
            _, pid, rrcount, _ = os.path.basename(file).split('.')
            procInfo = json.load(open(file, 'r'))
            significantRegions = procInfo['vads']
            print "loaded memory map for pid=" + pid, len(significantRegions)
            self.mmaps[int(pid)] = {i['start']: i for i in significantRegions}

    def get_region_data(self, pid, address, ignoreKind=False):
        map = self.mmaps[pid]
        allkeys = sorted(map.keys())
        keyidx = bisect_left(allkeys, address) - 1
        if keyidx < 0: return None
        key = allkeys[keyidx]
        vad = map[key]
        if address > vad['start'] and address < vad['end']:
            filename = vad.get('filename', "")
            filename = filename.split("\\")[-1] if filename else None
            protect = vad.get('protect',"").replace("READ", "R").replace("WRITE", "W").replace("EXECUTE_", "X")
            if ignoreKind:
                name = filename or "private" + protect + "_" + hex(vad['start']) 
            else:
                name = vad.get('kind') or filename or "private" + protect + "_" + hex(vad['start']) 
            return name, address - vad['start']
        else:
            return None

    def get_region_str(self, pid, address, ignoreKind=False):
        rdata = self.get_region_data(pid, address, ignoreKind)
        if rdata:
            region, offs = rdata
            return "{}+{}".format(region, hex(offs))
        else:
            return ""
    
    def firstExt(self, pid, entrypoints):
        for ep in entrypoints:
            f = self.get_region_str(pid, ep)
            if f: return f

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
            for i in f:
                if f["name"] not in ["BaseThreadInitThunk", "KiFastSystemCall", "ZwContinue"]:
                    return f["name"]

def printl(*stuff):
    print "\t".join(str(i) for i in stuff)

def hexa(a):
    return [hex(i) for i in a]

def printmatchhdr():
    printl("R/W", "K/U", "name", "asid", "address", "callstack_ids", "function_name", "callstack_function", "region")
    
def printmatch(i, pid, cdb, mmaps):
    kchar = "K" if i.get("in_kernel") else "U"
    fn = cdb.firstExt(i["callstack_fns"])
    region = mmaps.get_region_str(pid, i["callstack_fns"][0])
    #region2 = mmaps.get_region_str(pid, i["callstack_fns"])
    printl(i["kind"], kchar, i["name"], hex(i["asid"]), hex(i["last_addr"]), i["callstack_ids"][:4], fn, hexa(i["callstack_fns"][:2]), region)

def printmatchshort(i, pid, cdb, mmaps):
    fn = cdb.firstExt(i["callstack_fns"])
    region = mmaps.get_region_str(pid, i["callstack_fns"][0])
    #region2 = mmaps.get_region_str(pid, i["callstack_fns"])
    printl(i["kind"], i["name"], hex(i["asid"]), hex(i["last_addr"]), i["callstack_ids"][:2], fn, hexa(i["callstack_fns"][:2]), region)
    
import collections

class Syscalls:
    """Gives information about syscalls given their number"""

    def __init__(self):
        self.callnames = []

    def parse_prototypes(self, filename='windows7_x86_prototypes.txt'):
        with open(filename) as fproto:
            protos = fproto.readlines()
        self.callnames = [p.split(" ")[2] for p in protos]
        print "parsed {} prototypes".format(len(self.callnames))

    def syscall_name(self, number):
        if number > len(self.callnames):
            return None
        return self.callnames[number]


class CuckooReport:
    def __init__(self):
        self.report = dict()
        self.descriptions = dict()

    def load(self, filename="latest/reports/report.json"):
        self.report = json.load(open(filename))

        for process in self.report['behavior']['processes']:
            pid = process["pid"]
            for call in process["calls"]:
                call[u"pid"] = pid
                self.descriptions[call['uniqhash']] = call

    def processes_network_calls_count(self):
        """Summarizes the number of network calls for each process"""
        processes_summary = []
        for process in self.report['behavior']['processes']:
            calls = process["calls"]
            processes_summary.append({
                "pid": process["pid"],
                "path": process["process_path"],
                "calls": len(calls),
                "network_calls": sum(1 for call in calls if call.get("category") == "network"),
                "apis": set(call.get("api") for call in calls if call.get("category") == "network")
            })
        return processes_summary

    @staticmethod
    def calls_network_identifiers(calls):
        """returns the network identifiers (urls, ips, hostnames) used in a set of calls"""

        def identifiers(args):
            return args.get("url") or args.get("hostname") or args.get("ip_address") or args.get('path')

        network_calls_summary = []
        for call in calls:
            if call["category"] == "network":
                args = call.get("arguments")
                if not args: continue
                buff = args.get('buffer') or args.get("post_data") or []
                buflen = len(buff)
                identifier = identifiers(args)
                if identifier:
                    network_calls_summary.append({
                        "identifier": identifier,
                        "api": call["api"],
                        "buflen": buflen,
                        "uniqhash": call["uniqhash"]
                    })

        return network_calls_summary

    def calls_of_pid(self, pid):
        for process in self.report['behavior']['processes']:
            if int(process["pid"]) == int(pid):
                return process["calls"]

    def call_info(self, uniqhash):
        return self.descriptions.get(uniqhash)

    def locate_arg(self, argname, value):
        res = []
        for i in self.descriptions.values():
            a = i.get("arguments")
            if a:
                fh = a.get(argname)
                if fh == value:
                    res.append(i)
        return res
    
class MAccess:
    def __init__(self, access):
        self.value = access.value
        self.dependencies = list(access.dependencies)
        self.address = access.address
        self.argno = access.argno

import struct
import plog_pb2
class Event:
    def __init__(self, event):
        #self._event = event
        self.name = ""
        self.tags = []
        self.tagids = list(event.tags)
        self.dependencies = dict()
        self.tot_read = 0
        self.tot_written = 0
        self.effect = 0
        self.label = event.label
        self.asid = event.pid
        self.pid = 0
        self.reads = [MAccess(r) for r in event.reads]
        self.writes = [MAccess(w) for w in event.writes]
        self.kind = event.kind
        self.started = event.started
        self.ended = event.ended
        self.parent = event.parent
        self.thread = event.thread
        self.callstack = list(event.callstack)
        
    @property
    def t0(self):
        if self.tags:
            return self.tags[0]
        else:
            return {}
     
    @property
    def tl(self):
        if self.tags:
            return self.tags[-1]
        else:
            return {}
        
    def __str__(self):
        return "{}:{} in [{}]".format(self.label, self.name, ",".join(t.get('api') for t in self.tags))

    def __repr__(self):
        return self.__str__()

    def to_dict(self):
        return {
            "started": self.started,
            "name": self.name,
            "parent": self.parent,
            "reads": len(self.reads),
            "totread": self.tot_read,
            "writes": len(self.writes),
            "totwritten": self.tot_written,
            "effect": self.effect,
            "api": self.t0.get('api'),
            "apicat": self.t0.get('category'),
            "lapi": self.tl.get('api'),
            'lcat': self.tl.get('category'),
            "tag": self.t0.get('uniqhash'),
            "ltag": self.tl.get('uniqhash'),
            "othertags": self.tagids[1:],
            "tid": self.thread,
            "ended": self.ended,
            "deplen": len(self.dependencies),
            "deps": self.dependencies.keys(),
            "kind": self.kind,
            "label": self.label
        }

SYSCALL_KIND = 1
EVENT_KIND = 3
ENCCALL_KIND = 2
class Systaint():
    def __init__(self, syscalls, memorymaps, asidinfo, cdb, call_descriptions=dict()):
        self.events = None
        self.orderedEvents = []
        self.syscalls = syscalls
        self.effect = collections.Counter()
        self.memorymaps = memorymaps
        self.call_descriptions = call_descriptions
        self.asidinfo = asidinfo
        self.events_for_tag = collections.defaultdict(list)
        self.invdeps = defaultdict(set)
        self.cdb = cdb
        self.ignoreset = set()
        
    def pid_from_asid(self, asid):
        a = self.asidinfo.get(asid)
        if a:
            return a["pid"]
        else:
            return None

    def build_event(self, call):

        def name(event, pid):
            ep = event.entrypoint

            # todo differentiate using kind
            if event.kind == 1 :
                scname = self.syscalls.syscall_name(ep)
                if scname:
                    return scname

            if event.kind == 4:
                return "notif:{}".format(ep)
            
            # then ep is an address
            knownFunction = self.cdb.getName(ep)
            if knownFunction:
                return knownFunction['name']
            
            region = self.memorymaps.get_region_str(pid, ep)
            if region:
                return "{}({})".format(hex(ep), region)
            else:
                return "{}".format(hex(ep))

        event = Event(call)
        event.tot_read = sum(len(read.value) for read in call.reads)
        event.tot_written = sum(len(write.value) for write in call.writes)
        event.effect = self.effect[event.label]
        event.pid = self.pid_from_asid(call.pid)
        event.name = name(call, event.pid)
        
        deps = collections.defaultdict(int)
        for read in call.reads:
            for dep in read.dependencies:
                deps[dep] = deps[dep] + len(read.value)
                self.invdeps[dep].add(event.label)
                
        event.dependencies = deps

        return event

    @staticmethod
    def key(event):
        return str(event.label)

    def saveEvent(self, event):
        key = self.key(event)
        self.events[key] = event
        self.orderedEvents.append(event.label)

        for tag in event.tagids:
            self.events_for_tag[tag].append(event.label)
    
    def load(self, filename, force=False, ignoreNames=set()):
        self.events = shelve.open("tempdb", flag="n")
        ignoreCount = 0
        #if len(self.events) and not force:
        #    return

        with open(filename, 'rb') as f:
            while True:
                # read length
                lengthb = f.read(8)
                if not lengthb: break
                length = struct.unpack("Q", lengthb)[0]
                if length == 0:
                    print "LEN 0"
                    break
                
                # read a single call
                buf = f.read(length)
                if not buf: break

                # parse the call
                call = plog_pb2.SysFnCall()
                call.ParseFromString(buf)

                if call.kind == 5:
                    continue

                for read in call.reads:
                    self.effect.update(read.dependencies)

                event = self.build_event(call)
                
                ignoreEvent = False
                for name in ignoreNames:
                    if name in event.name:
                        ignoreCount += 1
                        ignoreEvent = True
                        break
                
                if not ignoreEvent:
                    self.saveEvent(event)

            print "parsed {} events".format(len(self.events))
            print "ignored {} events".format(ignoreCount)
            
    def event(self, identifier):
        if identifier in self.ignoreset:
            return None

        e = self.events.get(str(identifier))
        if e:
            e.tags = filter(None, (self.call_descriptions.get(t) for t in e.tagids))
            return e

    def debug_most_loud_calls(self):
        print "Calls marking the most data"
        print "id, marked, call"
        for i, j in self.effect.most_common(100):
            if i not in self.events:
                print "{}\t{}\t{}".format(i, j, "Discarded")
                continue
            event = self.events[i]
            print "{}\t{}\t{}".format(i, j, event.name)

    def debug_non_terminating(self):
        print "Non terminating syscalls: (didn't mark any data)"
        for e in self.evalues():
            if e.ended == 0:
                print e  # e.thread, e.label, e.started, e.name, e.entrypoint
                
    def print_read(self, read, pid=0):
        region = "unknown"
        if pid:
            regionname = self.memorymaps.get_region_str(pid, read.address)
            if regionname:
                region = regionname
        print "READ {}({}), len={}".format(hex(read.address), region, len(read.value))
        print ">> " + repr(read.value)
        if not read.dependencies: return
        dd = []
        for d in sorted(read.dependencies):
            ev = self.event(d)
            if ev:
                if ev.kind == ENCCALL_KIND:
                    dd.insert(0, "{}[{}]".format(d, ev.name))
                else:
                    dd.append("{}[{}]".format(d, ev.name))
            else:
                dd.append("unregistered")
        HOWMANY = 120
        remaining = len(dd) - HOWMANY
        remaining_str = "" if remaining < 0 else "and " + str(remaining) + " others"
        # print "LASTDEP {}".format(read.dependencies[-1])
        print "DEPS: {} {} ".format(",".join(dd[:HOWMANY]), remaining_str)


    def print_reads(self, event):
        print event.name, event.tags
        for i, r in enumerate(event.reads):
            print i
            self.print_read(r, event.pid)
            print

    def print_writes(self, event):
        print event.name, event.tags
        for i, w in enumerate(event.writes):
            print i
            self.print_read(w, event.pid)
            print

    def pre(self, eventid):
        return self.print_reads(self.event(eventid))

    def prw(self, eventid):
        return self.print_writes(self.event(eventid))

    def evalues(self):
        return self.events.itervalues()
    
def readsearch(string, events):
    if len(string) == 0:
        raise ValueError("zero length string")
        
    for e in events:
        found = False
        for i, read in enumerate(e.reads):
            match_position = read.value.find(string)
            if match_position != -1:
                yield (e, i, match_position)
                break

def writesearch(string, events):
    evs = []
    for e in events:
        for i, write in enumerate(e.writes):
            match_position = write.value.find(string)
            if match_position != -1:
                evs.append((e, i, match_position))
                break
    return evs

def labelsearch(label, events):
    calls = {}
    reads = []
    found = False
    for call in events:
        found = False
        for read in call.reads:
            if label in read.dependencies:
                reads.append((len(read.value), call.label, read))
                found = True
        if found:
            calls[call.label] = call
    return calls, reads


def extevents(filename):
    with open(filename, 'rb') as f:
        while True:
            # read length
            lengthb = f.read(8)
            if not lengthb: break
            length = struct.unpack("Q", lengthb)[0]

            if length > 100 * 1000 * 1000:
                print "skipping"
                f.seek(length, 1)
                continue

            if length == 0:
                print "LEN 0"
                break
            
            # read a single call
            buf = f.read(length)
            if not buf: break

            # parse the call
            call = plog_pb2.SysFnCall()
            call.ParseFromString(buf)
            if call.kind == 5:
                yield call
                
def compactbuffers(call, writes=False):
    result = []
    lastAddr = 0
    currBuff = b""
    accesses = call.writes if writes else call.reads
    for r in accesses:
        if r.address == lastAddr + 1:
            currBuff += r.value
            lastAddr += len(r.value)
        else:
            if currBuff: result.append(currBuff)
            currBuff = r.value
            lastAddr = r.address
    if currBuff: result.append(currBuff)
    return result

def tagsearch(tag, events):
    evs = []
    for e in events:
        if tag in e.tagids:
            evs.append(e)
    return evs


def color(kind):
    if kind == SYSCALL_KIND:
        return "red"
    else:
        return None

class Query:
    def __init__(self, systaint, depth, minsize):
        self.compactnodelist = []
        self.compactedgelist = []
        self.seenNodes = set()
        self.maxNodeLevel = defaultdict(int)
        self.maxDepth = depth
        self.minSize = minsize
        self.systaint = systaint
    
    def collectDeps(self, evid, deps, depth):
        if depth >= self.maxDepth:
            return
        for dep, w in deps.iteritems():
            if w < self.minSize:
                continue
            self.compactedgelist.append({"from": dep, "to": evid, "size": w, "arrows":'to'})
            
            e = self.systaint.event(dep)
            if e:
                #t = e.tags[-1].get('uniqhash') if e.tags else ""
                if dep not in self.seenNodes:
                    self.compactnodelist.append({"label": e.name.split("(")[0], "id": dep, "color": color(e.kind)})
                    self.seenNodes.add(dep)
                    self.collectDeps(dep, e.dependencies, depth + 1)
                self.maxNodeLevel[dep] = max(depth, self.maxNodeLevel[dep])
                
    
    def run(self, startset):
        self.startset = startset
        self.compactnodelist.append({"label": "query", "id": "query", "color": "magenta"}) # "level": 0
        self.collectDeps("query",  { i: 100 for i in startset} , 0)
        for i in self.compactnodelist:
            if i["id"] in startset:
                i["color"] = "orange"
        return self.compactnodelist, self.compactedgelist
        
#%%

# TODO: TEST
def findFrom(systaint, initialSet, maxDepth):
    cnodes = []
    cedges = []
    
    visitedSet = initialSet

    cnodes.append({"label": "query", "id": "query", "color": "magenta"})
    
    for evid in initialSet:
        e = systaint.event(evid)
        if not e:
            continue

        cnodes.append({"label": e.name.split("(")[0], "id": e.label, "color": "orange"})
        cedges.append({"from": "query" , "to":  e.label, "size": 100, "arrows":'to', "dashes": True})
    
    borderSet = set(initialSet)

    for n in range(1, maxDepth):
        for evid in set(borderSet):
            borderSet.remove(evid)
            visitedSet.add(evid)
            e = systaint.event(evid)
            if not e:
                continue
            
            for dependant in systaint.invdeps[evid]:
                dep = systaint.event(dependant)
                if not dep:
                    continue

                for d, size in dep.dependencies.iteritems():
                    if d == evid:
                        cedges.append({"from": dep, "to": evid, "size": size, "arrows":'to'})
                        break 

                if not (dependant in visitedSet or dependant in borderSet) :
                    cnodes.append({"label": dep.name.split("(")[0], "id": dep.label, "color": color(e.kind)})
                    borderSet.add(dependant)

    return cnodes, cedges


import cherrypy
import os
class App(object):
    
    def __init__(self, systaint, cuckoo_report, mmaps):
        self.systaint = systaint
        self.cuckoo_report = cuckoo_report
        self.mmaps = mmaps
        
    @cherrypy.expose
    def node(self, nodeid):
        ev = self.systaint.event(int(nodeid))
        
        if not ev:
            return None
        
        reads = []
        for r in ev.reads:
            addrdesc = self.mmaps.get_region_str(ev.pid, r.address)
            reads.append({"addr": r.address, "desc": addrdesc, "value": repr(r.value), "len": len(r.value) })
            
        return json.dumps({"event": ev.to_dict(), "reads": reads, "tag": ev.t0 })
        
    @cherrypy.expose
    def totag(self, tag, depth=3, mindepsize=3):
        depth = int(depth)
        mindepsize = int(mindepsize)
        q = Query(self.systaint, depth, mindepsize)
        tag = int(tag)
        cuckoo_call = self.cuckoo_report.call_info(tag)
        if cuckoo_call:
            initialSet = { e for e in self.systaint.events_for_tag[tag] }
        else:
            initialSet = set([tag])
        compactnodelist, compactedgelist = q.run(initialSet)
        return json.dumps({"edges": compactedgelist, "nodes": compactnodelist, "query": cuckoo_call })
    
    @cherrypy.expose
    def edge(self, frm, to):
        if to == "query" or frm == "query":
            return "[]"
        ev = self.systaint.event(int(to))
        frm = int(frm)
        reads = []
        for r in ev.reads:
            addrdesc = self.mmaps.get_region_str(ev.pid, r.address)
            for d in r.dependencies:
                if d == frm:
                    reads.append({"addr": r.address, "desc": addrdesc, "value": repr(r.value), "len": len(r.value) })
                    break
        return json.dumps(reads)
    
    @cherrypy.expose
    def fromtag(self, tag, depth=1):
        tag = int(tag)
        depth = int(depth)
        cuckoo_call = self.cuckoo_report.call_info(tag)
        if cuckoo_call:
            initialSet = { e for e in self.systaint.events_for_tag[tag] }
        else:
            initialSet = set([tag])
        cnodes, cedges = findFrom(self.systaint, initialSet, depth)
        return json.dumps({"edges": cedges, "nodes": cnodes, "query": cuckoo_call})

def startServer(systaint, cuckoo_report, mmaps):
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': os.path.abspath(os.getcwd())
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': '../static'
        }
    }
    cherrypy.quickstart(App(systaint, cuckoo_report, mmaps), '/', conf)