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

from ghidra.feature.fid import *  # type: ignore
from ghidra.feature.fid.db import *  # type: ignore
from ghidra.feature.fid.service import *  # type: ignore
from ghidra.program.model.listing import (
    Function,
    FunctionIterator,
    FunctionManager,
)

libraryTag = (currentProgram.
                getFunctionManager().
                getFunctionTagManager().
                getFunctionTag("LIBRARY"))

def processMatches(analysis, result):
    if result.matches.size() == 0:
        return

    fn: Function = result.function
    if not fn.getTags().contains(libraryTag):
        print(f"Trying to tag fn {fn} that isn't a library")
        return

    analysis.analyzeNames(result.matches, currentProgram, monitor)
    if analysis.getMostOptimisticCount() > 1:
        return

    if analysis.numNames() != 1:
        return

    libs = set()
    for match in result.matches:
        libRec = match.getLibraryRecord()
        libName: str = libRec.getLibraryFamilyName()
        libs.add(libName.upper())

    for lib in libs:
        fn.addTag(lib)

def run():
    fm: FunctionManager = currentProgram.getFunctionManager()
    fnIt: FunctionIterator = fm.getFunctions(True)

    fidService = FidService() # type: ignore
    fidQuerySvc = fidService.openFidQueryService(currentProgram.getLanguage(), False)
    analysis = MatchNameAnalysis() # type: ignore

    processProg = fidService.processProgram(
        currentProgram,
        fidQuerySvc,
        14.6, # default from FidService.java
        monitor
    )

    for entry in processProg:
        if entry.function.isThunk():
            continue

        if not entry.matches.isEmpty():
            processMatches(analysis, entry)

run()
