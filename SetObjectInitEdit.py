#TODO write a description for this script
#@author 
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

# -*- coding: utf-8 -*-

# For VS Code type checking stuff
try:
    from typing import TYPE_CHECKING
except:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.listing import Function, ParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    CategoryPath, PointerDataType, StructureDataType
)
from pprint import pprint
from functools import partial

globalIfc = None

from GhidraUtils import *

def main():
    # Must do this before doing any other calls from GhidraUtils
    # otherwise all the ghidra global/FlatProgramAPI/GhidraScript functions
    # won't exist
    AdoptGlobals(globals())
    # Use the function we're currently in
    targetFn = getFunctionContaining(currentAddress)
    if not targetFn:
        printerr("Function containing addr {} doesn't exist".format(currentAddress))
        return

    objName = targetFn.getName().rsplit("_",1)[0]

    println("Object name: {}".format(objName))

    dtm = currentProgram.getDataTypeManager()
    taskDT = dtm.getDataType(CategoryPath("/task"), "task")
    taskwkDT = dtm.getDataType(CategoryPath("/character"), "taskwk")

    objTaskName = "{}_task".format(objName)
    objTaskwkName = "{}_taskwk".format(objName)
    objPath = CategoryPath("/objects/{}".format(objName))
    targetFnArg0 = targetFn.getParameter(0)
    if targetFnArg0 == None or targetFnArg0.getFormalDataType().isEquivalent(PointerDataType(taskDT)):
        newTaskDT = CopyDataType(taskDT, objTaskName, objPath)

        newTaskwkDT = CopyDataType(taskwkDT, objTaskwkName, objPath)
        # 13 on PC, will be different on at least DC due to fewer TaskFunctions
        newTaskDT.replace(13, PointerDataType(newTaskwkDT), -1,
                          newTaskDT.getComponent(13).getFieldName(),
                          newTaskDT.getComponent(13).getComment())

        ptrNewDT = PointerDataType(newTaskDT)
        thisParam = ParameterImpl("this", ptrNewDT, currentProgram, SourceType.USER_DEFINED)
        targetFn.replaceParameters(
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True, SourceType.USER_DEFINED,
            [thisParam] # type: ignore
        ) # type: ignore
    else:
        ptrNewDT = PointerDataType(dtm.getDataType(objPath, objTaskName))

    globalIfc = open_ifc(currentProgram)

    retVal = GenerateFnTokenMaps(globalIfc, targetFn, monitor)
    if retVal == None:
        printerr("[!] Token maps didn't get generated!")
        return
    fnNameMap, fieldMap = retVal

    #println("Functions:")
    #pprint(fnNameMap)

    #println("Fields:")
    #pprint(fieldMap)

    # Do some more variable naming
    ProcessThresholdWithFn = partial(ProcessThreshold, fn=targetFn)
    if not DoCallbackIfOneItem(fnNameMap, ProcessThresholdWithFn, "object_delete_if_past_distance_threshold"):
        printerr("Failed this check")
        #return

    NameActionwkWithFn = partial(NameActionwk, fn=targetFn)
    if not DoCallbackIfOneItem(fieldMap, NameActionwkWithFn, "action_struct"):
        printerr("Failed this check")

    # Custom data type for this specific Set Object
    ProcessMallocWithName = partial(ProcessMalloc, baseName="{}".format(objName), fn=targetFn)
    if not DoCallbackIfOneItem(fieldMap, ProcessMallocWithName, "malloc"):
        printerr("Failed this check")
        #return

    # Collision hitboxes
    ProcessCollisionWithName = partial(ProcessCollisionInit, name="{}_CollisionElements".format(objName))
    if not DoCallbackIfOneItem(fnNameMap, ProcessCollisionWithName, "collision_init_q"):
        printerr("Failed this check")
        #return

    # Callback functions on task 
    ProcessDisplayFunction = partial(ProcessCallbackFunction, fnName="{}_display".format(objName), taskDT=ptrNewDT)
    if not DoCallbackIfOneItem(fieldMap, ProcessDisplayFunction, "display_function"):
        printerr("Failed this check")
        #return

    ProcessUpdateFunction = partial(ProcessCallbackFunction, fnName="{}_update".format(objName), taskDT=ptrNewDT)
    if not DoCallbackIfOneItem(fieldMap, ProcessUpdateFunction, "update_function"):
        printerr("Failed this check")
        #return

    ProcessDeleteFunction = partial(ProcessCallbackFunction, fnName="{}_delete".format(objName), taskDT=ptrNewDT)
    if not DoCallbackIfOneItem(fieldMap, ProcessDeleteFunction, "delete_function"):
        printerr("Failed this check")
        #return


if __name__ == "__main__":
    main()