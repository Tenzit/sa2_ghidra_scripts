#@author Tenzit
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

# For VS Code type checking stuff
try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import importlib
import logging
import sys
from typing import cast

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.app.services import ConsoleService
from ghidra.graph import DefaultGEdge
from ghidra.graph.jung import JungDirectedGraph
from ghidra.program.database import ProgramDB
from ghidra.program.model.data import DataTypeWriter
from ghidra.program.model.listing import Function
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.util import AcyclicCallGraphBuilder
from ghidra.util.graph import *
from java.io import FileWriter  # type: ignore

sys.stdout = getState().getTool().getService(
    ConsoleService
).getStdOut() # type: ignore

import DumpDatatypes  # noqa: I001
importlib.reload(sys.modules['DumpDatatypes'])
from DumpDatatypes import *  # pyright: ignore[reportGeneralTypeIssues] # noqa: E402, I001

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.WARNING, force=True, stream=sys.stdout)

def SetupDecompiler(program: ProgramDB) -> DecompInterface:
    ifc = DecompInterface()
    ifcOptions = DecompileOptions()
    ifcOptions.setRespectReadOnly(True)
    ifcOptions.setEliminateUnreachable(True)
    ifc.setOptions(ifcOptions)
    ifc.setSimplificationStyle("decompile")
    ifc.openProgram(program)

    return ifc

def CommitSignature(function: Function, ifc: DecompInterface):
    highFunc = ifc.decompileFunction(fn, 0, monitor).getHighFunction()
    HighFunctionDBUtil.commitParamsToDatabase(
        highFunc,
        True,
        HighFunctionDBUtil.ReturnCommitOption.COMMIT,
        SourceType.USER_DEFINED
    )

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

ifc = SetupDecompiler(currentProgram)

libFns = set()
nonLibFns = set()
successors = jungGraph.getSuccessors(currFn)
fn: Function
for fn in successors:
    if fn.getSignatureSource() not in (SourceType.USER_DEFINED, SourceType.IMPORTED):
        logger.info(f"Committing signature for function {fn}")
        CommitSignature(fn, ifc)

    if fn in libraryFns:
        libFns.add(fn)
    else:
        nonLibFns.add(fn)

logger.info(f"Library functions: {libFns}")
logger.info(f"Non-library functions: {nonLibFns}")

dtMap = BuildTypeToFuncMap({currFn}, libFns, nonLibFns, ifc, monitor)

combinedDtMap = defaultdict(set)
for dt, fns in dtMap.items():
    reducedFns = set()
    for fn in fns:
        if fn in {currFn}:
            reducedFns.add(currFn.getName())
        elif fn in libFns:
            reducedFns.add("library functions")
        elif fn in nonLibFns:
            reducedFns.add("non-library functions")
    combinedDtMap[dt] = reducedFns

combinedDtMap, combinedUniqueDtMap = GetUniqueDTs(combinedDtMap)

fnMap = BuildInvertedMap(dtMap)
combinedFnMap = BuildInvertedMap(combinedDtMap)
# test
for fn, dts in combinedUniqueDtMap.items():
    logger.info(f"Function {fn} is the only user of:")
    for dt in dts:
        logger.info(f"    {dt.getName()}")

for dt, fns in combinedDtMap.items():
    logger.info(f"DataType {dt.getName()} is used in:")
    for fn in fns:
        logger.info(f"    {fn}")

dirBase="C:/Users/Tenzit/Documents/GitHub/sa2_ghidra_scripts/output"

fw = FileWriter(f"{dirBase}/fn.h")
fnDtWriter = DataTypeWriter(currentProgram.getDataTypeManager(), fw)
fnDtWriter.write([*combinedFnMap[currFn.getName()], *combinedUniqueDtMap[currFn.getName()]], monitor)
fw.close() # type: ignore
fw = FileWriter(f"{dirBase}/lib.h")
libDtWriter = DataTypeWriter(currentProgram.getDataTypeManager(), fw)
libDtWriter.write([*combinedFnMap["library functions"], *combinedUniqueDtMap["library functions"]], monitor)
fw.close() # type: ignore
fw = FileWriter(f"{dirBase}/nonlib.h")
nonLibDtWriter = DataTypeWriter(currentProgram.getDataTypeManager(), fw)
nonLibDtWriter.write([*combinedFnMap["non-library functions"], *combinedUniqueDtMap["non-library functions"]], monitor)
fw.close() # type: ignore
