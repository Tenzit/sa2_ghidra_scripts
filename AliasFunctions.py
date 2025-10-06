#Used for Dreamcast stuff, takes functions in 
#0xa0xxxxxx and 0x40xxxxxx and aliases them to
#the functions in 0x80xxxxxx because
#of how dreamcast handles this
#@author Tenzit
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

import argparse
from typing import Optional, List, Dict, TypeVar
import typing

from GhidraArgumentParser import GhidraArgumentParser
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
from ghidra.program.model.listing import Function, FunctionIterator
from ghidra.program.model.mem import Memory
from ghidra.program.model.address import AddressSet, Address
from functools import partial

def GetOrCreateFunction(addr: Address) -> Optional[Function]:
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionAt(addr)
    if f:
        return f
    try:
        f = createFunction(addr, None)
        disassemble(f.getEntryPoint())
        return createFunction(addr, None)  # auto-name
    except Exception as e:
        print("Failed to create function at {}: {}".format(addr, e))
        return None

def EnsureThunk(aliasFunc: Function, baseFunc: Function) -> None:
    """Make aliasFunc a thunk that forwards to baseFunc."""
    try:
        if aliasFunc.isThunk():
            tf = aliasFunc.getThunkedFunction(True)
            if tf is baseFunc:
                return
        aliasFunc.setThunkedFunction(baseFunc)
    except Exception as e:
        print("Failed to set thunk for {} -> {}: {}".format(aliasFunc.getEntryPoint(),
                                                           baseFunc.getEntryPoint(), e))

def GetFunctionsInBlock(blockName: str) -> List[Function]:
    """
    Return functions whose entry points are within the named memory block.
    Uses AddressSet-constrained iterator (Ghidra 11.3.1).
    """
    mem = currentProgram.getMemory()
    block = mem.getBlock(blockName)
    if block is None:
        raise RuntimeError('Memory block "{}" not found.'.format(blockName))
    aset = AddressSet(block.getAddressRange())

    funcs: List[Function] = []
    it: FunctionIterator = currentProgram.getFunctionManager().getFunctions(aset, True)  # forward within the set
    it.forEachRemaining(lambda f: funcs.append(f))
    return funcs

def Run():
    parser: GhidraArgumentParser = GhidraArgumentParser()
    parser.add_argument("block", type=str, help="Name of the block to alias functions from",
                        on_missing=partial(askString, "Block", "Block name?"))
    parser.add_argument("delta", type=int, help="Offset from alias->base",
                        on_missing=partial(askInt, "Delta", "Delta to base?"))

    args = parser.parse_args(list(getScriptArgs() or []))
    BLOCK_NAME: str = args.block
    DELTA: int = args.delta

    println(f"Delta: {DELTA}")

    mem: Memory = currentProgram.getMemory()
    block = mem.getBlock(BLOCK_NAME)
    if block is None:
        raise RuntimeError('Memory block "{}" not found.'.format(BLOCK_NAME))

    fm = currentProgram.getFunctionManager()

    funcsInBlock = GetFunctionsInBlock(BLOCK_NAME)
    processed = 0
    createdBase = 0
    thunked = 0

    for aliasFunc in funcsInBlock:
        if monitor.isCancelled():
            break

        processed += 1
        baseAddr = aliasFunc.getEntryPoint().subtract(DELTA)

        baseFunc = fm.getFunctionAt(baseAddr)
        if baseFunc is None:
            baseFunc = GetOrCreateFunction(baseAddr)
            if baseFunc:
                createdBase += 1
        if baseFunc is None:
            continue

        EnsureThunk(aliasFunc, baseFunc)
        thunked += 1

    print('Block                 : "{}"'.format(BLOCK_NAME))
    print("Alias funcs processed : {}".format(processed))
    print("Base funcs created    : {}".format(createdBase))
    print("Aliases thunked       : {}".format(thunked))
    print("Done.")

# Entry
Run()
