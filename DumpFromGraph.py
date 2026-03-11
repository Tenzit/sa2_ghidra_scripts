#@author Tenzit
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

# For VS Code type checking stuff
try:
    from typing import TYPE_CHECKING
except:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from typing import cast

from ghidra.program.model.util import AcyclicCallGraphBuilder
from ghidra.util.graph import *
from ghidra.graph import DefaultGEdge
from ghidra.graph.jung import JungDirectedGraph
from ghidra.program.model.listing import Function
from ghidra.program.model.address import AddressSet
from ghidra.program.database import ProgramDB
from ghidra.app.decompiler import DecompInterface, DecompileOptions

def GetFunctionsWithTag(program: ProgramDB, tagName: str) -> set[Function]:
    fnMan = program.getFunctionManager()
    tag = program.getFunctionManager().getFunctionTagManager().getFunctionTag(tagName)
    taggedFns = set()

    fnIt = fnMan.getFunctions(True)
    while fnIt.hasNext():
        fn: Function = cast(Function, fnIt.next())
        if tag in fn.getTags():
            taggedFns.add(fn)

    return taggedFns

builder = AcyclicCallGraphBuilder(currentProgram, True)
depGraph = builder.getDependencyGraph(monitor)
jungGraph = JungDirectedGraph()

libraryFns = GetFunctionsWithTag(currentProgram, "LIBRARY")
ctorFns = GetFunctionsWithTag(currentProgram, "CONSTRUCTOR")

while depGraph.hasUnVisitedIndependentValues():
    for val in depGraph.getUnvisitedIndependentValues():
        valFn = getFunctionAt(val)
        jungGraph.addVertex(valFn)
        deps = depGraph.getDependentValues(val)
        for dep in deps:
            depFn = getFunctionAt(dep)
            jungGraph.addVertex(depFn)
            if depFn not in libraryFns:
                jungGraph.addEdge(DefaultGEdge(depFn, valFn))
        depGraph.remove(val)

currFn = getFunctionContaining(currentAddress)
calledFuncs = jungGraph.getSuccessors(currFn)
print(f"{currFn} successors: {calledFuncs}")

ifc = DecompInterface()
ifcOptions = DecompileOptions()
ifcOptions.setRespectReadOnly(True)
ifcOptions.setEliminateUnreachable(True)
ifc.setOptions(ifcOptions)
ifc.setSimplificationStyle("decompile")
ifc.openProgram(currentProgram)

res = ifc.decompileFunction(currFn, 0, monitor)

#print(f"GetC: {res.getDecompiledFunction().getC()}")
#print(f"{res.getDecompiledFunction().getSignature()}")
print(f"{currFn.getSignature()}")
symbols = res.getHighFunction().getGlobalSymbolMap().getSymbols()
for sym in symbols:
    print(f"Is global: {sym.isGlobal()}; {sym.getDataType()} {sym.getName()}")

fnDts = set()
print("/////////Local symbols//////////")
for sym in res.getHighFunction().getLocalSymbolMap().getSymbols():
    print(f"{sym.getDataType()} {sym.getName()}")
    fnDts.add(sym.getDataType())

print("/////////Global symbols//////////")
for sym in res.getHighFunction().getGlobalSymbolMap().getSymbols():
    print(f"{sym.getDataType()} {sym.getName()}")
    fnDts.add(sym.getDataType())

print("/////////return//////////")
print(f"{res.getHighFunction().getFunctionPrototype().getReturnType()}")
fnDts.add(res.getHighFunction().getFunctionPrototype().getReturnType())

libFns = set()
nonLibFns = set()
successors = jungGraph.getSuccessors(currFn)
for fn in successors:
    if fn in libraryFns:
        libFns.add(fn)
    else:
        nonLibFns.add(fn)

libDts = set()
print("/////////Library functions//////////")
for fn in libFns:
    decFn = ifc.decompileFunction(fn, 0, monitor)
    print(f"{decFn.getDecompiledFunction().getSignature()}")
    libDts.add(decFn.getHighFunction().getFunctionPrototype().getReturnType())
    proto = decFn.getHighFunction().getFunctionPrototype()
    for i in range(proto.getNumParams()):
        print(f"{proto.getParam(i).getDataType()}", end=' ')
        libDts.add(proto.getParam(i).getDataType())
    print("")

nonLibDts = set()
print("/////////Non-library functions//////////")
for fn in nonLibFns:
    decFn = ifc.decompileFunction(fn, 0, monitor)
    print(f"{decFn.getDecompiledFunction().getSignature()}")
    nonLibDts.add(decFn.getHighFunction().getFunctionPrototype().getReturnType())
    proto = decFn.getHighFunction().getFunctionPrototype()
    for i in range(proto.getNumParams()):
        print(f"{proto.getParam(i).getDataType()}", end=' ')
        nonLibDts.add(proto.getParam(i).getDataType())
    print("")

#addrSet = AddressSet(currFn.getBody())
#
from ghidra.app.util.exporter import CppExporter
from ghidra.program.model.data import DataTypeWriter
from java.io import File, FileWriter # type: ignore

dirBase="C:/Users/Tenzit/Documents/GitHub/sa2_ghidra_scripts/output"

fnDtWriter = DataTypeWriter(currentProgram.getDataTypeManager(), FileWriter(f"{dirBase}/fn.h"))
fnDtWriter.write(list(fnDts), monitor)
libDtWriter = DataTypeWriter(currentProgram.getDataTypeManager(), FileWriter(f"{dirBase}/lib.h"))
libDtWriter.write(list(libDts), monitor)
nonLibDtWriter = DataTypeWriter(currentProgram.getDataTypeManager(), FileWriter(f"{dirBase}/nonlib.h"))
nonLibDtWriter.write(list(nonLibDts), monitor)

#exporter = CppExporter(ifcOptions, True, True, False, False, "Tag")
#
#exporter.export(File("C:/Users/Tenzit/Documents/GitHub/sa2_ghidra_scripts/test.c"), currentProgram, addrSet, monitor)