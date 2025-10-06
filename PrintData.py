#TODO write a description for this script
#@author 
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


from ghidra.program.model.listing import Data

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *


def recursePrint(data):
    if data.isArray() or data.isStructure():
        for i in range(0, data.getNumComponents()):
            recursePrint(data.getComponent(i))
    else:
        print("({}){}{} = {}".format(data.getPrimitiveAt(0).getDataType().getDisplayName(), data.getRoot().getLabel(), data.getComponentPathName(), data.getPrimitiveAt(0).getDefaultValueRepresentation()))

def main():
    root = getDataContaining(currentAddress)
    if root is None:
        printerr("Put the pointer on data")
        return

    recursePrint(root)

if __name__ == '__main__':
    main()