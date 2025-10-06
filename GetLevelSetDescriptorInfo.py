#TODO write a description for this script
#@author 
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

# -*- coding: utf-8 -*-

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

try:
    from typing import TYPE_CHECKING
except:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from GhidraArgumentParser import GhidraArgumentParser
from functools import partial

from pprint import pprint
import csv
import io

TIMEOUT_SECS = 60

def write_csv(rows):
    outFile = askFile("CSV File", "Save")

    with io.open(outFile.getAbsolutePath(), "wb") as f:
        w = csv.writer(f) # type: ignore
        for r in rows:
            print(r)
            w.writerow(r)

def open_ifc(program):
    ifc = DecompInterface()
    ifc.openProgram(program)
    return ifc

def decompile_func(ifc, func, monitor):
    return ifc.decompileFunction(func, TIMEOUT_SECS, monitor or ConsoleTaskMonitor())

def parse_level_set_descriptor(lsd):
    if lsd.getDataType().getDisplayName() != "LevelSetDescriptor":
        printerr("  [!] Data passed in to `parse_level_set_descriptor` is not a LevelSetDescriptor!")
        return set()

    numElems = lsd.getComponent(0).getValue().getValue()

    setFileDescArrayPtr = lsd.getComponent(1)

    sfdArray = getDataAt(setFileDescArrayPtr.getValue())
    

    setObjs = set()
    # Could probably check that sfdArray.numComponents() == numElems, but whatever
    for i in range(0, numElems):
        elem = sfdArray.getComponent(i)
        tf = elem.getComponent(4).getValue()
        eName = getDataAt(elem.getComponent(5).getValue()).getValue().strip().upper()
        setObjs.add((eName, tf))

    return setObjs

def inspect_call_site(ifc, caller, target, arg_index, parser):
    """Decompile caller at call_addr, fetch argument type, print members."""
    if caller is None:
        printerr("  [!] No caller function found for {}".format(caller))
        return set()

    res = decompile_func(ifc, caller, monitor)
    if not res or not res.getDecompiledFunction():
        printerr("  [!] Decompilation failed for caller {}".format(caller.getName()))
        return set()

    ccode = res.getCCodeMarkup()

    it = ccode.tokenIterator(True)
    line = None
    while it.hasNext():
        tok = it.next()
        if tok.getClass().getSimpleName() == "ClangFuncNameToken" and tok.getText() == target.getName():
            line = tok.getLineParent()
            break
    if line == None:
        printerr("   [!] No line containing function {} found.".format(target.getName()))
        return set()

    lineToks = line.getAllTokens()

    argIdx = 0
    argVal = None
    for lineTok in lineToks:
        if lineTok.getClass().getSimpleName() == "ClangVariableToken":
            if argIdx == arg_index:
                argVal = lineTok.getText()
                break
            argIdx = argIdx + 1

    if argVal == None:
        printerr("   [!] Could not find arg at idx {}. Only had {} args.".format(arg_index, argIdx))

    argSymbol = getSymbols(argVal, None) # type: ignore

    if len(argSymbol) == 0:
        printerr("   [!] Could not find symbol {} in {} in {}.".format(argVal, line, caller))
        return set()

    if len(argSymbol) > 1:
        printerr("   [!] More than 1 symbol {}. Don't handle picking which yet, oops".format(argVal))
        return set()

    argSymbol = argSymbol[0]
    argData = getDataAt(argSymbol.getAddress())

    return parser(argData)
 
def main():
    # Pick the callee
    parser: GhidraArgumentParser = GhidraArgumentParser()
    parser.add_argument("callee", type=str, help="Function whose call sites you want to inspect",
                        on_missing=partial(askString, "Callee", "Callee path?"))
    parser.add_argument("idx", type=int, help="0-based idx of the function arg to inspect",
                        on_missing=partial(askInt, "Index", "Function Arg Index?"))
    args = parser.parse_args(list(getScriptArgs() or []))
    target = args.target
    if target is None:
        printerr("No function chosen.")
        return

    targetFnList = getGlobalFunctions(target)

    if not targetFnList:
        printerr("Function with name {} doesn't exist".format(target))

    targetFn = targetFnList[0]

    # Which argument?
    arg_index = args.idx

    println("=== Inspecting argument {} at all call sites to '{}' ===".format(arg_index, targetFn.getName()))

    ifc = open_ifc(currentProgram)

    # Direct calls via xrefs
    all_sites = targetFn.getCallingFunctions(None).toArray()
    #all_sites = getReferencesTo(targetFn.getEntryPoint())
    println("[*] Found {} direct call site(s) via xrefs.".format(len(all_sites)))

    setObjDict = {}
    for callingFnRef in all_sites:
        fnSetObjs = inspect_call_site(ifc, callingFnRef, targetFn, arg_index, parse_level_set_descriptor)
        for fnSetObj in fnSetObjs:
            if fnSetObj not in setObjDict:
                setObjDict[fnSetObj] = [callingFnRef.getName()]
            else:
                setObjDict[fnSetObj].append(callingFnRef.getName())

    rows = [[u"Obj name", u"Obj init func", u"callers..."]]
    for k, v in setObjDict.items():
        r = list(k)
        r = r + v
        rows.append(r)

    write_csv(rows)

    println("\n=== Done. {} call site(s) processed. ===".format(len(all_sites)))

if __name__ == "__main__":
    main()
