#Finds structures that directly use a given data type
#@author 
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


#TODO Add User Code Here


from ghidra.program.model.data import DataTypeManager, StructureDataType, PointerDataType
from ghidra.program.database.data import StructureDB, PointerDB

try:
    from typing import TYPE_CHECKING
except:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from GhidraArgumentParser import GhidraArgumentParser
from functools import partial

parser: GhidraArgumentParser = GhidraArgumentParser()
parser.add_argument("datatype", type=str, help="Full path of the datatype",
                    on_missing=partial(askString, "Datatype", "Datatype path?"))
args = parser.parse_args(list(getScriptArgs() or []))

TARGET_DATA_TYPE_NAME = args.datatype

dtm = currentProgram.getDataTypeManager()
target_dt = dtm.getDataType(TARGET_DATA_TYPE_NAME) # Get the target data type

if target_dt is None:
    popup("Target data type '%s' not found." % TARGET_DATA_TYPE_NAME)
else:
    found_structures = []
    # Iterate through all data types in the program
    for dt in dtm.getAllDataTypes():
        if monitor.isCancelled():
            break
        if isinstance(dt, (StructureDataType,StructureDB)): # type: ignore
            # Check if the structure contains the target data type as a component
            for component in dt.getComponents():
                if component.getDataType() == target_dt:
                    found_structures.append(dt)
                    break # Found it in this structure, move to the next structure

    if found_structures:
        println("Structures using '%s':" % TARGET_DATA_TYPE_NAME)
        for struct in found_structures:
            println("\n%s" % (struct))
    else:
        println("No structures found using '%s'." % TARGET_DATA_TYPE_NAME)
