#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import struct
from rekall import session
from rekall import plugins  # required
from rekall import addrspace
from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays.windows import pe_vtypes
import os

import json
from IPython import embed
import IPython.core.page


# Disable IPython's pager
def page_printer(data, start=0, screen_lines=0, pager_cmd=None):
    if isinstance(data, dict):
        data = data['text/plain']
    print(data)


IPython.core.page.page = page_printer

# Set up logger for rekall
logging.basicConfig(level=logging.DEBUG)

# Import pypanda embedded module
import panda


class PandaAddressSpace(addrspace.BaseAddressSpace):
    """An address space that exposes QEMU's phyisical memory through panda's functions."""

    __name = "Panda"

    order = 100

    # This address space handles images.
    __image = True

    def __init__(self, **kwargs):
        super(PandaAddressSpace, self).__init__(**kwargs)

    def read(self, addr, length):
        length = int(length)
        addr = int(addr)
        try:
            data = panda.read(addr, length)
            return data + addrspace.ZEROER.GetZeros(length - len(data))
        except IOError:
            return addrspace.ZEROER.GetZeros(length)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_mappings(self, start=0, end=2 ** 64):
        _ = end
        yield addrspace.Run(start=0, end=panda.memory_size(),
                            file_offset=0, address_space=self)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return True

    def close(self):
        pass

    def __eq__(self, other):
        return self.__class__ == other.__class__

first = True

def run(val):
    global s
    global first
    s = create_session()
    s.physical_address_space = PandaAddressSpace(session=s)
    print("current rrcount ", panda.get_rr_count())
    if first:
        interactive()
        first = False
    dumpFullInfo(val)


def create_session(filename=None):
    global s
    s = session.Session(
        filename=filename,
        autodetect=["rsds"],
        logger=logging.getLogger(),
        autodetect_scan_length=18446744073709551616,
        profile="nt/GUID/00625D7D36754CBEBA4533BA9A0F3FE22",
        profile_path=["http://profiles.rekall-forensic.com"])

    print("session created")
    return s


def dumpProcess(pid):
    dirname = "dump_{}".format(pid)
    try:
        os.mkdir(dirname)
    except Exception as e:
        print(e)
    for i in s.plugins.dlldump(pid, dump_dir=dirname).collect():
       print(i)
    #print(s.plugins.memdump(pid, dump_dir=dirname))
    print(s.plugins.vaddump(pid, dump_dir=dirname))


def vads(pid):
    """
    {'VAD': [_MMVAD_LONG _MMVAD_LONG] @ 0x847DE288,
     '_EPROCESS': [_EPROCESS _EPROCESS] @ 0x84A8C458 (pid=2404),
     'com':  [BitField(0-19):CommitCharge]: 0x00000001,
     'end': <None Pointer to [0x00020fff] (Pointer)>,
     'exe': '',
     'filename': '',
     'lev': 6,
     'protect':  [Enumeration:Enumeration]: 0x00000004 (READWRITE),
     'start': <None Pointer to [0x00020000] (Pointer)>,
     'type': 'Private'}
    """
    return s.plugins.vad(pid).collect()



def getheaps(eprocess):
    return [int(h) for h in eprocess.Peb.ProcessHeaps.dereference()]


def getstacks(eprocess):
    result = []
    for thread in eprocess.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
        teb = s.profile._TEB(
            offset=thread.Tcb.Teb,
            vm=eprocess.get_process_address_space())
        if teb:
            result.append(int(teb.NtTib.StackBase))
    return result


def processes():
    return s.plugins.pslist().collect()

def findExportsFromLoadedDLLs(pid):
    p = process(pid)
    eprocess = p['_EPROCESS']
    modules = eprocess.get_load_modules()

    exports = {}
    for i, mod in enumerate(modules):
        pe = pe_vtypes.PE(address_space=mod.obj_vm,
                          session=s, image_base=mod.DllBase)

        for _, func_pointer, func_name, ordinal in pe.ExportDirectory():
            function_name = func_name or ordinal or ''
            exports[func_pointer.v()] = (mod, func_pointer, function_name)

    return exports

def dumpExports(pid):
    exports = findExportsFromLoadedDLLs(pid)
    filename = "process.{}.AsDLLExports.csv".format(pid)
    with open(filename, "w") as f:
        for pointer, tuple in exports.items():
            mod, fnp, fnameb = tuple
            modname = str(mod.BaseDllName)
            fnoffset = pointer - mod.base
            fname = str(fnameb)
            f.write("{:#010x}, {}, {}, {}\n".format(pointer, fname, modname, fnoffset))

def fullinfo(pid):
    p = process(pid)
    eprocess = p['_EPROCESS']

    heaps = getheaps(eprocess)
    stacks = getstacks(eprocess)

    result_vads = []
    for vad in vads(pid):
        if 'start' not in vad:
            continue

        result_vad = {
            'start': int(vad['start']),
            'end': int(vad['end']),
            'filename': vad.get('filename'),
            'protect': str(vad.get('protect')),
            'kind': ''
        }

        address = int(vad['start'])
        if address in heaps:
            result_vad['kind'] = "Heap"
        elif address in stacks:
            result_vad['kind'] = "Stack"

        result_vads.append(result_vad)

    return {
        'vads': result_vads,
        'heaps': heaps,
        'stacks': stacks
    }


def dumpFullInfo(pid):
    infos = fullinfo(pid)
    rrcount = panda.get_rr_count()

    infos['rrcount'] = rrcount
    infos['pid'] = pid

    filename = "processInfo.{}.{}.json".format(pid, rrcount)
    json.dump(infos, open(filename, "w"), indent=2)

    dumpExports(pid)
    dumpProcess(pid)
    print("dumped {}".format(filename))


def process(pid):
    """
     {'_EPROCESS': [_EPROCESS _EPROCESS] @ 0x840ECD40 (pid=2696),
      'handle_count':  [unsigned long:HandleCount]: 0x00000000,
      'ppid':  [unsigned int:InheritedFromUniqueProcessId]: 0x0000058c,
      'process_create_time':  [WinFileTime:CreateTime]: 0x5a1e9e50 (2017-11-29 11:47:28Z),
      'process_exit_time':  [WinFileTime:ExitTime]: 0x00000000 (-),
      'session_id':  [unsigned long:SessionId]: 0x00000001,
      'thread_count':  [unsigned long:ActiveThreads]: 0x00000001,
      'wow64': False},
    """
    try:
        return next(s.plugins.pslist(pid).collect())
    except:
        raise KeyError("no such process found")


def interactive():
    embed()


if __name__ == '__main__':
    s = create_session("/home/vigliag/thesis/december-workdirs/zeus2017-11-29/memdump.7755311328.raw")
    interactive()
