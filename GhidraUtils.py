#Only use this as an import 
#@author 
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import Function, ParameterImpl, LocalVariableImpl, VariableUtilities
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    CategoryPath, PointerDataType, DataTypeConflictHandler,
    VoidDataType, ArrayDataType, StructureDataType, DataUtilities,
    UnsignedIntegerDataType
)
from ghidra.app.cmd.function import SetVariableNameCmd
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.pcode import HighFunctionDBUtil

from ghidra.util.task import ConsoleTaskMonitor

class Bail(Exception):
    pass

def BailIfNone(value, message):
    if value is None:
        raise Bail(message)
    return value

def BailIfNotOne(value, messageIf0, messageifGt1):
    if len(value) == 0:
        raise Bail(messageIf0)
    elif len(value) > 1:
        raise Bail(messageifGt1)
    return value

def WithBail():
    def decorator(fn):
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Bail as b:
                ghidraPrinterr(str(b))
                return
        return wrapper
    return decorator

def AdoptGlobals(g):
    global api
    api = FlatProgramAPI(g['currentProgram'], g['monitor'])
    global ghidraPrintln
    global ghidraPrinterr
    ghidraPrintln = g['println']
    ghidraPrinterr = g['printerr']

def GetToken(tokIt, n, kind, stopAt=None, startAfter=None):
    """
    Return the 0-based n-th token matching (kind, text), optionally:
      - stopAt=(kind,text): stop scanning when this token is seen (exclude it)
      - startAfter=(kind,text): ignore tokens until this token is seen
    """
    def tokenNameCheck(tok, name):
        return tok.getClass().getSimpleName() == name

    if startAfter is not None:
        startKind, startText = startAfter
        for tok in tokIt:
            if tokenNameCheck(tok, startKind) and tok.getText() == startText:
                break

    count = 0
    for tok in tokIt:
        if stopAt is not None:
            stopKind, stopText = stopAt
            if tokenNameCheck(tok, stopKind) and tok.getText() == stopText:
                return None

        if tokenNameCheck(tok, kind):
            if count == n:
                return tok
            count += 1

    return None

def open_ifc(program):
    ifc = DecompInterface()
    ifc.openProgram(program)
    return ifc

TIMEOUT_SECS = 60
def decompile_func(ifc, func, monitor):
    return ifc.decompileFunction(func, TIMEOUT_SECS, monitor or ConsoleTaskMonitor())

def CopyDataType(dt, newName, path):
    dtm = api.currentProgram.getDataTypeManager()
    tx = dtm.startTransaction("Copy datatype for Object")
    try:
        newDT = dt.copy(dtm)
        newDT.setName(newName)
        newDT.setCategoryPath(path)
        added = dtm.addDataType(newDT, DataTypeConflictHandler.KEEP_HANDLER)
        return added
    finally:
        dtm.endTransaction(tx, True)

def AddToMap(m, key, value):
    if key not in m:
        m[key] = [value]
    else:
        m[key].append(value)

def GenerateFnTokenMaps(ifc, caller, monitor):
    res = decompile_func(ifc, caller, monitor)
    if not res or not res.getDecompiledFunction():
        ghidraPrinterr("  [!] Decompilation failed for caller {}".format(caller.getName()))
        return

    ccode = res.getCCodeMarkup()

    it = ccode.tokenIterator(True)
    fnNameMap = {}
    fieldMap = {}
    while it.hasNext():
        tok = it.next()
        if tok.getClass().getSimpleName() == "ClangFuncNameToken":
            AddToMap(fnNameMap, tok.getText(), tok.getLineParent())
        elif tok.getClass().getSimpleName() == "ClangFieldToken":
            AddToMap(fieldMap, tok.getText(), tok.getLineParent())
            
    return (fnNameMap, fieldMap)

def DoCallbackIfOneItem(mapStruct, callback, key):
    if key not in mapStruct:
        ghidraPrinterr("[!]: Key {} not map!".format(key))
        return False
    v = mapStruct[key]
    if len(v) == 0:
        ghidraPrinterr("[!]: No items in map for {}".format(key))
        return False
    elif len(v) > 1:
        ghidraPrinterr("[!]: More than 1 item in map for {}".format(key))
        return False
    else:
        callback(v[0])
        return True

@WithBail()
def ProcessCallbackFunction(line, fnName, taskDT):
    lineTokIt = iter(line.getAllTokens())
    varTok = GetToken(lineTokIt, 1, "ClangVariableToken")
    varTok = BailIfNone(varTok, "[!]: No variable found to set to {}".format(fnName))
    #ghidraPrintln("{} = {}; dt = {}".format(fnName, varTok, taskDT.getName()))
    varSym = api.getSymbols(varTok.getText(), None) # type: ignore

    varSym = BailIfNotOne(varSym,
        "[!]: No symbol found for {}".format(varTok),
        "[!]: Multiple symbols found for {}".format(varTok))[0]

    fn = api.getFunctionAt(varSym.getAddress())
    if fn == None:
        fn = api.createFunction(varSym.getAddress(), fnName)
    else:
        if varSym.getSource() != SourceType.USER_DEFINED:
            fn.setName(fnName, SourceType.USER_DEFINED)

    fn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
    thisParam = ParameterImpl("this", taskDT, api.currentProgram, SourceType.USER_DEFINED)
    fn.replaceParameters(
        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
        True, SourceType.USER_DEFINED,
        [thisParam] # type: ignore
    ) # type: ignore

@WithBail()
def ProcessCollisionInit(line, name):
    lineToksIt = iter(line.getAllTokens())
    dataTok = GetToken(lineToksIt, 1, kind="ClangVariableToken")
    numTok = GetToken(lineToksIt, 0, kind="ClangVariableToken") # relative

    dataLoc = BailIfNone(dataTok,
        "[!]: No variable found for the CollisionElement array! (Would be named {})".format(name)
    ).getText()
    dataSym = api.getSymbols(dataLoc, None) # type: ignore
    dataSym = BailIfNotOne(dataSym,
        "[!]: No symbol found for {}".format(dataLoc),
        "[!]: Multiple symbols found for {}".format(dataLoc))[0]

    numElems = BailIfNone(numTok,
        "[!]: No variable for number of elements found!"
    ).getScalar().getValue()

    existingData = api.getDataAt(dataSym.getAddress())

    dtm = api.currentProgram.getDataTypeManager()
    collisionElementDT = dtm.getDataType(CategoryPath("/collision"), "CollisionElement")
    collisionElementArrayDT = ArrayDataType(collisionElementDT, numElems, collisionElementDT.getLength())

    if existingData == None or not existingData.getDataType().isEquivalent(collisionElementArrayDT):
        existingData = DataUtilities.createData(
            api.currentProgram, dataSym.getAddress(), collisionElementArrayDT,
            -1, False,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
 
    if dataSym.getSource() != SourceType.USER_DEFINED:
        dataSym.setName(name, SourceType.USER_DEFINED)

def CreateLocalVar(fn, varTok, name, dt = None):
    varStorage = varTok.getHighVariable().getSymbol().getStorage()

    if varStorage.isUniqueStorage():
        tx = api.currentProgram.startTransaction("Commit unique var")
        try:
            HighFunctionDBUtil.updateDBVariable(
                varTok.getHighVariable().getSymbol(),
                name,
                varTok.getHighVariable().getDataType() if dt == None else dt,
                SourceType.USER_DEFINED,
            )
        finally:
            api.currentProgram.endTransaction(tx, True)
    else:
        # Maybe change this?
        VariableUtilities.checkVariableConflict(fn, None, varStorage, True) # type: ignore
        localVar = LocalVariableImpl(
            name,
            varTok.getVarnode().getPCAddress().subtract(fn.getEntryPoint()),
            varTok.getHighVariable().getDataType(),
            varStorage,
            True,
            api.currentProgram,
            SourceType.USER_DEFINED
        )

        fn.addLocalVariable(localVar, SourceType.USER_DEFINED)

@WithBail()
def ProcessMalloc(line, baseName, fn):
    lineTokIt = iter(line.getAllTokens())
    assignVar = GetToken(lineTokIt, 0, "ClangVariableToken",
                         stopAt=("ClangFieldToken", "malloc"))
    dtLenTok = GetToken(lineTokIt, 0, "ClangVariableToken",
                        startAfter=("ClangFieldToken", "malloc"))

    assignVar = BailIfNone(assignVar, "[!]: No variable being assigned the result of the malloc!")
    if not assignVar.isVariableRef():
        ghidraPrinterr("[!]: Variable malloc is being assigned to isn't a variable reference!")
        return
    
    dtLen = BailIfNone(dtLenTok,
        "[!]: No variable for datatype length found! (Object with dt to be defined: {}".format(baseName)
    ).getScalar().getValue()

    dtm = api.currentProgram.getDataTypeManager()
    custDTPath = CategoryPath("/objects/{}".format(baseName))
    # Make base DT
    baseCustDT = StructureDataType(
        custDTPath, "{}_CustData".format(baseName), dtLen - 4, dtm)

    # Have to make the wrapper DT on PC
    wrapperCustDT = StructureDataType(
        custDTPath, "{}_CustDataWrapper".format(baseName), 0, dtm)    
    wrapperCustDT.add(UnsignedIntegerDataType.dataType, 4, "magic", None)
    wrapperCustDT.add(baseCustDT, -1, "data", None)

    tx = dtm.startTransaction("Add {} custom data DTs".format(baseName))
    try:
        baseCustDT = dtm.resolve(baseCustDT, DataTypeConflictHandler.KEEP_HANDLER)
        wrapperCustDT = dtm.resolve(wrapperCustDT, DataTypeConflictHandler.KEEP_HANDLER)
    finally:
        dtm.endTransaction(tx, True)

    if not assignVar.getHighVariable().getDataType().isEquivalent(PointerDataType(wrapperCustDT)):
        CreateLocalVar(fn, assignVar, "custDataWrapped", PointerDataType(wrapperCustDT))

@WithBail()
def ProcessThreshold(line, fn):
    lineTokIt = iter(line.getAllTokens())

    #for tok in lineTokIt:
    #    ghidraPrintln("{}: {}".format(tok.getClass().getSimpleName(), tok.getText()))

    assignTok = GetToken(lineTokIt, 0, "ClangVariableToken",
                         stopAt=("ClangFuncNameToken", "object_delete_if_past_distance_threshold"))
    renderDistTok = GetToken(lineTokIt, 1, "ClangVariableToken",
                        startAfter=("ClangFuncNameToken", "object_delete_if_past_distance_threshold"))

    assignVar = BailIfNone(assignTok, "[!]: No variable being assigned the result of render distance check!")
    if not assignVar.isVariableRef():
        ghidraPrinterr("[!]: Return value of render distance check isn't a variable reference!")
        return

    renderDistVar = BailIfNone(renderDistTok, "[!]: Variable that contains render distance doesn't exist!")
    if not renderDistVar.isVariableRef():
        ghidraPrinterr("[!]: Render distance var isn't a variable reference!")
        return

    ghidraPrintln("{}".format(fn.getAllVariables()))

    CreateLocalVar(fn, renderDistVar, "objRenderDist")
    CreateLocalVar(fn, assignVar, "playerOutOfObjRenderDist")

@WithBail()
def NameActionwk(line, fn):
    lineTokIt = iter(line.getAllTokens())

    assignTok = GetToken(lineTokIt, 0, "ClangVariableToken")
    assignVar = BailIfNone(assignTok, "[!]: No variable being assigned task actionwk!")

    if not assignVar.isVariableRef():
        ghidraPrinterr("[!]: Assigning actionwk to something that isn't a variable!")

    CreateLocalVar(fn, assignVar, "thisActionwk")