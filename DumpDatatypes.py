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

import logging
from collections import defaultdict
from typing import Any, TypeVar

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import Array, DataType, Pointer
from ghidra.program.model.listing import Function
from ghidra.util.task import TaskMonitor

logger = logging.getLogger(__name__)

def UnwrapTypes(dt: DataType) -> DataType:
    if isinstance(dt, Array) or isinstance(dt, Pointer):
        logger.info(f"Unwrapping dt {dt.getName()}")

    while isinstance(dt, Array) or isinstance(dt, Pointer):
        dt = dt.getDataType()
        logger.info(f"    --> {dt.getName()}, type: {type(dt)}")

    return dt

def GetFnDataTypes(
    function: Function,
    ifc: DecompInterface,
    monitor: TaskMonitor
) -> set[DataType]:
    dts = set()

    res = ifc.decompileFunction(function, 0, monitor)

    for sym in res.getHighFunction().getLocalSymbolMap().getSymbols():
        unwrapped = UnwrapTypes(sym.getDataType())
        dts.add(unwrapped)

    for sym in res.getHighFunction().getGlobalSymbolMap().getSymbols():
        unwrapped = UnwrapTypes(sym.getDataType())
        dts.add(unwrapped)

    unwrapped = UnwrapTypes(res.getHighFunction().getFunctionPrototype().getReturnType())
    dts.add(unwrapped)

    return dts

def GetFnProtoTypes(
    function: Function,
    ifc: DecompInterface,
    monitor: TaskMonitor
) -> set[DataType]:
    dts = set()

    res = ifc.decompileFunction(function, 0, monitor)
    unwrapped = UnwrapTypes(res.getHighFunction().getFunctionPrototype().getReturnType())
    dts.add(unwrapped)
    proto = res.getHighFunction().getFunctionPrototype()
    for i in range(proto.getNumParams()):
        unwrapped = UnwrapTypes(proto.getParam(i).getDataType())
        dts.add(unwrapped)

    return dts

def BuildTypeToFuncMap(
    functions: set[Function],
    libFns: set[Function],
    nonLibFns: set[Function],
    ifc: DecompInterface,
    monitor: TaskMonitor
) -> dict[DataType, set[Function]]:
    typeMap = defaultdict(set)

    for fn in functions:
        fnDts = GetFnDataTypes(fn, ifc, monitor)
        for dt in fnDts:
            typeMap[dt].add(fn)

    for fn in libFns:
        fnDts = GetFnProtoTypes(fn, ifc, monitor)
        for dt in fnDts:
            typeMap[dt].add(fn)

    for fn in nonLibFns:
        fnDts = GetFnProtoTypes(fn, ifc, monitor)
        for dt in fnDts:
            typeMap[dt].add(fn)

    return typeMap

def BuildFuncToTypeMap(
    functions: set[Function],
    libFns: set[Function],
    nonLibFns: set[Function],
    ifc: DecompInterface,
    monitor: TaskMonitor
) -> dict[DataType, set[Function]]:
    fnMap = defaultdict(set)

    for fn in functions:
        fnDts = GetFnDataTypes(fn, ifc, monitor)
        for dt in fnDts:
            fnMap[fn].add(dt)

    for fn in libFns:
        fnDts = GetFnProtoTypes(fn, ifc, monitor)
        for dt in fnDts:
            fnMap[fn].add(dt)

    for fn in nonLibFns:
        fnDts = GetFnProtoTypes(fn, ifc, monitor)
        for dt in fnDts:
            fnMap[fn].add(dt)

    return fnMap

def BuildBothMaps(
    functions: set[Function],
    libFns: set[Function],
    nonLibFns: set[Function],
    ifc: DecompInterface,
    monitor: TaskMonitor
) -> tuple[dict[Function, set[DataType]], dict[DataType, set[Function]]]:
    fnMap = defaultdict(set)
    typeMap = defaultdict(set)

    for fn in functions:
        fnDts = GetFnDataTypes(fn, ifc, monitor)
        for dt in fnDts:
            fnMap[fn].add(dt)
            typeMap[dt].add(fn)

    for fn in libFns:
        fnDts = GetFnProtoTypes(fn, ifc, monitor)
        for dt in fnDts:
            fnMap[fn].add(dt)
            typeMap[dt].add(fn)


    for fn in nonLibFns:
        fnDts = GetFnProtoTypes(fn, ifc, monitor)
        for dt in fnDts:
            fnMap[fn].add(dt)
            typeMap[dt].add(fn)


    return fnMap, typeMap

K = TypeVar('K')
V = TypeVar('V')
def BuildInvertedMap(
    mapToInvert: dict[K, set[V]],
) -> dict[Any, set[Any]]:
    invertedMap = defaultdict(set)

    for k, v in mapToInvert.items():
        for thing in v:
            invertedMap[thing].add(k)

    return invertedMap


def GetUniqueDTs(
    typeMap: dict[K, set[V]]
) -> tuple[dict[K, set[V]], dict[V, set[K]]]:
    uniqueDtMap = defaultdict(set)

    delList = set()
    for k, v in typeMap.items():
        if len(v) == 1:
            for fn in v:
                uniqueDtMap[fn].add(k)
            delList.add(k)

    for item in delList:
        del typeMap[item]

    return typeMap, uniqueDtMap