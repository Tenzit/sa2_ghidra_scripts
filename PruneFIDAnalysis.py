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

from ghidra.program.model.symbol import SourceType

bookman = currentProgram.getBookmarkManager()
symTab = currentProgram.getSymbolTable()

removeMe = []
bmIt = bookman.getBookmarksIterator("Analysis")
libTag = currentProgram.getFunctionManager().getFunctionTagManager().getFunctionTag("LIBRARY")
bms = bookman.getBookmarks(currentAddress)
while bmIt.hasNext(): # type: ignore
    bm = bmIt.next() # type: ignore
    if bm.getCategory() != "Function ID Analyzer":
        continue
    bmFn = getFunctionContaining(bm.getAddress())
    if bmFn is None:
        continue
    fnLabels = symTab.getSymbols(bmFn.getEntryPoint())
    if not bmFn.getTags().contains(libTag):
        bmFn.addTag("LIBRARY")
        print(f"Checking over function {bmFn}")
    else:
        removeMe.append(bm)
        continue
    allAnalysis = True
    analysisLabelCount = 0
    labelToUse = None
    labelToRemove = None

    for label in fnLabels:
        if label.getSource() == SourceType.USER_DEFINED and label.isPrimary():
            print(f"    {label} :: {label.getSource()} {label.isPrimary()} {label.getSymbolType()}")
            labelToRemove = label
        elif label.getSource() != SourceType.ANALYSIS:
            print(f"    {label} :: {label.getSource()} {label.isPrimary()} {label.getSymbolType()}")
            allAnalysis = False
            break
        else:
            labelToUse = label
            analysisLabelCount = analysisLabelCount + 1
            print(f"    {label} :: {label.getSource()} {label.isPrimary()} {label.getSymbolType()}")
    if labelToRemove is not None:
        if analysisLabelCount == 1 and labelToUse is not None:
            name = labelToUse.getName()
            labelToUse.delete()
            bmFn.setName(name, SourceType.ANALYSIS)
        else:
            continue
    if allAnalysis:
        removeMe.append(bm)

for rm in removeMe:
    bookman.removeBookmark(rm)