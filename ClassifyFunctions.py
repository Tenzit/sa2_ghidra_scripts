#Classifies which functions can be
#reached from a given base function
#Additionally, if they can be reached, 
#are they exclusively reached from said function
#@author Tenzit
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

from functools import partial
from typing import Set, Dict, List, Tuple, Optional, Deque, Any, TypedDict
from collections import deque
import csv

import typing

from GhidraArgumentParser import GhidraArgumentParser
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.listing import Function
from ghidra.util.task import TaskMonitor
from ghidra.program.model.address import Address, AddressSetView, AddressSpace
from ghidra.program.model.mem import Memory
from docking.widgets.filechooser import GhidraFile


class ResultSets(TypedDict):
    AppReachable: Set[Function]
    ExclusiveAppReachable: Set[Function]
    ImportStub: Set[Function]
    External: Set[Function]
    Unreached: Set[Function]
    AllFunctions: Set[Function]
    ClassByFunc: Dict[Function, str]


def GetFunction(addr) -> Optional[Function]:
    """
    Return the Function containing the given addr, or None if not inside a function.
    """
    if addr is None:
        return None
    addrAddr = toAddr(addr)
    functionManager = currentProgram.getFunctionManager()
    func: Optional[Function] = functionManager.getFunctionContaining(addrAddr)
    return func


def IsImportThunk(func: Function) -> bool:
    """
    A function is an 'import thunk' if it's a thunk whose thunked target is an external function.
    """
    if not func.isThunk():
        return False
    target: Optional[Function] = func.getThunkedFunction(True)
    return (target is not None) and target.isExternal()


def GetCallees(func: Function, monitor: TaskMonitor) -> Tuple[Set[Function], Set[Function], Set[Function]]:
    """
    Return (internalCallees, importStubsUsed, externalsUsed) using the built-in API.
    Only functions that Ghidra has resolved will appear here.
    """
    internalCallees: Set[Function] = set()
    importStubsUsed: Set[Function] = set()
    externalsUsed: Set[Function] = set()

    for callee in func.getCalledFunctions(monitor):
        if callee.isExternal():
            externalsUsed.add(callee)
        else:
            internalCallees.add(callee)

    return internalCallees, importStubsUsed, externalsUsed


def ClassifyAll(rootFunc: Function, monitor: TaskMonitor) -> ResultSets:
    """
    Compute classification sets starting at rootFunc, stopping at externals and import thunks.
    Also returns a direct lookup map ClassByFunc for O(1) classification retrieval.
    """
    functionManager = currentProgram.getFunctionManager()

    # All defined functions
    allFunctions: Set[Function] = set()
    functionIter = functionManager.getFunctions(True)
    while functionIter.hasNext() and not monitor.isCancelled():
        fn: Function = functionIter.next()
        allFunctions.add(fn)

    # Program-wide externals & import thunks
    allImportStubs: Set[Function] = {fn for fn in allFunctions if IsImportThunk(fn)}
    allExternals: Set[Function] = {fn for fn in allFunctions if fn.isExternal()}

    # BFS from root, stopping at externals and import thunks
    appReachable: Set[Function] = set()
    workDeque: Deque[Function] = deque([rootFunc])
    appReachable.add(rootFunc)

    while workDeque and not monitor.isCancelled():
        fn: Function = workDeque.popleft()
        internalCallees, _, _ = GetCallees(fn, monitor)
        for callee in internalCallees:
            if (callee not in appReachable
                and callee not in allImportStubs
                and callee not in allExternals):
                appReachable.add(callee)
                workDeque.append(callee)

    # Final classification precedence: External > ImportStub > AppReachable > Unreached
    unreached: Set[Function] = {
        fn for fn in allFunctions
        if fn not in allExternals and fn not in allImportStubs and fn not in appReachable
    }

    # ---- Callers-based exclusivity ----
    # Cache internal callers to avoid re-iterating Ghidra DB repeatedly.
    callersCache: Dict[Function, Set[Function]] = {}

    def GetInternalCallers(func: Function) -> Set[Function]:
        cached = callersCache.get(func)
        if cached is not None:
            return cached
        internal: Set[Function] = set()
        caller: Function
        for caller in func.getCallingFunctions(monitor):
            # Ignore externals and import thunks as "outside" edges;
            # we only care about internal program callers.
            if (caller.isExternal() or caller.isThunk()
                or caller.getEntryPoint().getAddressSpace().isOverlaySpace()):
                continue
            internal.add(caller)
        callersCache[func] = internal
        return internal

    # Memoize "has an outside (non-app) caller path"
    hasOutsideCallerMemo: Dict[Function, bool] = {}
    hasOutsideCallerMemo[rootFunc] = False

    def HasOutsideCaller(func: Function, visiting: Set[Function]) -> bool:
        """
        True if there exists a path via getCallingFunctions() from some internal function
        NOT in appReachable into 'func'. (Extern/import callers are ignored.)
        """
        memoVal = hasOutsideCallerMemo.get(func)
        if memoVal is not None:
            return memoVal

        visiting.add(func)
        for caller in GetInternalCallers(func):
            if caller not in appReachable:
                hasOutsideCallerMemo[func] = True
                visiting.discard(func)
                return True
            # caller is inside the app tree; recurse unless we’re in a cycle
            if caller not in visiting and HasOutsideCaller(caller, visiting):
                hasOutsideCallerMemo[func] = True
                visiting.discard(func)
                return True
        visiting.discard(func)
        hasOutsideCallerMemo[func] = False
        return False

    exclusiveAppReachable: Set[Function] = set()
    for fn in appReachable:
        if not HasOutsideCaller(fn, set()):
            exclusiveAppReachable.add(fn)

    # Build a single lookup table to avoid repeated set membership checks in CSV build
    classByFunc: Dict[Function, str] = {fn: "Unreached" for fn in allFunctions}
    for fn in appReachable:
        classByFunc[fn] = "AppReachable"
    for fn in allImportStubs:
        classByFunc[fn] = "ImportStub"   # overrides AppReachable if any overlap (shouldn't)
    for fn in allExternals:
        classByFunc[fn] = "External"     # highest precedence
    for fn in exclusiveAppReachable:
        if fn not in allImportStubs and fn not in allExternals:
            classByFunc[fn] = "ExclusiveAppReachable"


    return {
        "AppReachable": appReachable,
        "ExclusiveAppReachable": exclusiveAppReachable,
        "ImportStub": allImportStubs,
        "External": allExternals,
        "Unreached": unreached,
        "AllFunctions": allFunctions,
        "ClassByFunc": classByFunc
    }


def BuildCsvRows(resultSets: ResultSets) -> List[Dict[str, Any]]:
    """
    Build CSV rows from the classification sets using the precomputed ClassByFunc mapping.
    """
    memory: Memory = currentProgram.getMemory()
    rows: List[Dict[str, Any]] = []

    functionsSorted: List[Function] = sorted(
        resultSets["AllFunctions"],
        key=lambda fn: fn.getEntryPoint().getOffset()
    )

    classByFunc: Dict[Function, str] = resultSets["ClassByFunc"]

    for fn in functionsSorted:
        entry: Address = fn.getEntryPoint()
        space: AddressSpace = entry.getAddressSpace()
        spaceName: str = space.getName()
        body: Optional[AddressSetView] = fn.getBody()
        sizeBytes: int = int(body.getNumAddresses()) if body is not None else 0

        if classByFunc.get(fn, "Unreached") != "Unreached":
            rows.append({
                "functionName": fn.getName() or "",
                "entryAddress": str(entry),
                "classification": classByFunc.get(fn, "Unreached"),
                "isThunk": "Y" if fn.isThunk() else "N",
                "isExternal": "Y" if fn.isExternal() else "N",
                "memorySpace": spaceName,
                "sizeBytes": sizeBytes
            })
    return rows


def WriteCsv(outputPath: str, rows: List[Dict[str, Any]]) -> None:
    """
    Write the rows to a CSV file.
    """
    fieldNames: List[str] = [
        "functionName", "entryAddress", "classification",
        "isThunk", "isExternal", "memorySpace", "sizeBytes"
    ]
    with open(outputPath, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldNames)
        writer.writeheader()
        writer.writerows(rows)


def Run() -> None:
    """
    Entry point: classify and export to CSV using the selected function as root.
    """
    monitor.setMessage("Classifying functions and exporting CSV...")

    parser: GhidraArgumentParser = GhidraArgumentParser()
    parser.add_argument("addr", type=str, help="Address of function to use as root",
                        default=currentAddress)
    args = parser.parse_args(list(getScriptArgs() or []))

    rootFunc: Optional[Function] = GetFunction(args.addr)
    if rootFunc is None:
        raise Exception("No function found. Place the caret inside the desired root function or pass in root function addr and re-run.")

    results: ResultSets = ClassifyAll(rootFunc, monitor)
    rows: List[Dict[str, Any]] = BuildCsvRows(results)

    outFile: GhidraFile = askFile("Save function classification CSV", "Save")
    if outFile is None:
        raise Exception("No output selected; aborted.")

    WriteCsv(outFile.getAbsolutePath(), rows)

    print("\n=== App/Library Classification (CSV written) ===")
    print("Root: {} @ {}".format(rootFunc.getName(), rootFunc.getEntryPoint()))
    print("AppReachable : {}".format(len(results["AppReachable"])))
    print("ExclusiveAppReachable : {}".format(len(results["ExclusiveAppReachable"])))
    print("ImportStub   : {}".format(len(results["ImportStub"])))
    print("External     : {}".format(len(results["External"])))
    print("Unreached    : {}".format(len(results["Unreached"])))
    print("Output CSV   : {}".format(outFile.getAbsolutePath()))
    print("Done.")


# Entry
Run()

