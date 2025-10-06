#TODO write a description for this script
#@author 
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

try:
    from typing import TYPE_CHECKING
except:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from GhidraUtils import *

from functools import partial

def main():
    AdoptGlobals(globals())

    targetFn = getFunctionContaining(currentAddress)
    if not targetFn:
        printerr("Function containing addr {} doesn't exist".format(currentAddress))
        return

    globalIfc = open_ifc(currentProgram)

    retVal = GenerateFnTokenMaps(globalIfc, targetFn, monitor)
    if retVal == None:
        printerr("[!] Token maps didn't get generated!")
        return
    fnNameMap, fieldMap = retVal

    ProcessThresholdWithFn = partial(ProcessThreshold, fn=targetFn)
    if not DoCallbackIfOneItem(fnNameMap, ProcessThresholdWithFn, "object_delete_if_past_distance_threshold"):
        printerr("Failed this check")
 
    NameActionwkWithFn = partial(NameActionwk, fn=targetFn)
    if not DoCallbackIfOneItem(fieldMap, NameActionwkWithFn, "action_struct"):
        printerr("Failed this check")

if __name__ == "__main__":
    main()