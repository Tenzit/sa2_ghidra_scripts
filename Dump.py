#Decompiles and dumps the current function to a c file
#@author 
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

import os, re
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util.bin import MemoryByteProvider

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

# ---------- helpers ----------

def SanitizeName(s):
    s = (s or "noname")
    s = re.sub(r'[^A-Za-z0-9_.-]+', '_', s)
    return s if re.match(r'[A-Za-z_]', s[0]) else "_" + s

def EnsureDir(path):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d)

def WriteUtf8(path, text):
    EnsureDir(path)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

def DataCName(addr):
    sym = currentProgram.getSymbolTable().getPrimarySymbol(addr)
    name = sym.getName() if sym and sym.getAddress() == addr else "DAT_{}".format(addr)
    name = re.sub(r'[^A-Za-z0-9_]', '_', name)
    return name if re.match(r'[A-Za-z_]', name[0]) else "_" + name

def BytesToLiteral(barr):
    vals = ["0x%02X" % (b & 0xFF) for b in barr]
    return ",\n  ".join([", ".join(vals[i:i+12]) for i in range(0, len(vals), 12)])

def ReadBytes(addr, length):
    """
    Zero-copy-ish read using MemoryByteProvider (no JArray).
    Returns a Java byte[] (still indexable/sliceable in PyGhidra).
    """
    provider = MemoryByteProvider(currentProgram.getMemory(), addr)
    try:
        return provider.readBytes(0, length)  # returns Java byte[]
    except Exception as e:
        # Fallback: truncate at the largest readable span if the request crossed an unmapped gap.
        # Probe backward until it succeeds or length hits 0.
        n = length
        while n > 0:
            try:
                return provider.readBytes(0, n)
            except Exception:
                n //= 2
        return bytearray(0)  # empty


def IsQuotedString(data):
    try:
        rep = data.getDefaultValueRepresentation() or ""
        return rep.startswith('"') and rep.endswith('"')
    except:
        return False

# ---------- core ----------

def GetCurrentFunction():
    return getFunctionContaining(currentAddress)

def CollectDataAddrs(func):
    listing = currentProgram.getListing()
    rm = currentProgram.getReferenceManager()
    out = set()
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext():
        ins = it.next()
        for r in rm.getReferencesFrom(ins.getMinAddress()):
            to = r.getToAddress()
            if not (to and to.isMemoryAddress()):
                continue
            d = listing.getDefinedDataAt(to) or listing.getDataContaining(to)
            if d:
                out.add(d.getMinAddress())
    return out

def ExportFunction(func, outDir, timeoutSec=60):
    di = DecompInterface()
    di.setOptions(DecompileOptions())
    di.openProgram(currentProgram)
    res = di.decompileFunction(func, timeoutSec, monitor or ConsoleTaskMonitor())

    banner = "/* {} {} */\n".format(func.getEntryPoint(), func.getName())
    body = ("/* DECOMPILE FAILED: {} */\n".format(res.getErrorMessage())
            if not res.decompileCompleted()
            else res.getDecompiledFunction().getC() + "\n")

    path = os.path.join(outDir, "func_{}_{}.c".format(func.getEntryPoint(), SanitizeName(func.getName())))
    prolog = "/* Decompiled with Ghidra — Program: {} */\n\n".format(
        currentProgram.getDomainFile().getName())
    WriteUtf8(path, prolog + banner + body)
    return path

def ExportData(addrs, outDir):
    listing = currentProgram.getListing()
    hPath = os.path.join(outDir, "ghidra_data.h")
    cPath = os.path.join(outDir, "ghidra_data.c")

    hLines = ["/* Auto-generated — referenced data */", "#pragma once", "#include <stdint.h>", ""]
    cLines = ['/* Auto-generated — referenced data */', '#include "ghidra_data.h"', ""]

    for a in sorted(addrs, key=lambda x: int(x.getOffset())):
        d = listing.getDefinedDataAt(a) or listing.getDataContaining(a)
        name = DataCName(a)
        if d is None:
            hLines.append("extern const uint8_t {}[8];".format(name))
            cLines.append("const uint8_t {}[8] = {{ /* undefined @ {} */ 0 }};".format(name, a))
            continue

        size = d.getLength()
        cmt = "/* {} @ {} (size {}) */".format(d.getDataType().getName(), a, size)

        if IsQuotedString(d):
            lit = d.getDefaultValueRepresentation()
            hLines.append("extern const char {}[];".format(name))
            cLines.append("{}\nconst char {}[] = {};".format(cmt, name, lit))
        else:
            bytesArr = ReadBytes(a, size)
            hLines.append("extern const uint8_t {n}[{s}];".format(n=name, s=len(bytesArr)))
            cLines.append("{}\nconst uint8_t {}[{}] = {{\n  {}\n}};".format(
                cmt, name, len(bytesArr), BytesToLiteral(bytesArr)))

    WriteUtf8(hPath, "\n".join(hLines) + "\n")
    WriteUtf8(cPath, "\n".join(cLines) + "\n")
    return hPath, cPath

def Run():
    func = GetCurrentFunction()
    if func is None:
        printerr("Move the cursor into a function and run again.")
        return

    outDirFile = askDirectory("Choose output directory", "Select")
    if outDirFile is None:
        printerr("Cancelled.")
        return
    outDir = outDirFile.getAbsolutePath()

    funcPath = ExportFunction(func, outDir)
    dataAddrs = CollectDataAddrs(func)
    hPath, cPath = ExportData(dataAddrs, outDir)
    println("Wrote:\n  {}\n  {}\n  {}".format(funcPath, hPath, cPath))

Run()
