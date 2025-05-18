# Reverse Cyberpunk symbol hashes for defined class namespaces
#@author Mozz
#@category Symbol
#@keybinding 
#@menupath 
#@toolbar 

import json
from java.util import HashSet
from javax.swing import SwingUtilities

from docking.widgets.dialogs import TableSelectionDialog
from docking.widgets.table import TableColumnDescriptor

from ghidra.app.plugin.core.symtable import SymbolRowObject, TransientSymbolTableModel

from ghidra.app.util.demangler.microsoft import MicrosoftDemangler, MicrosoftMangledContext, MicrosoftDemanglerOptions

from ghidra.util.table.field import AbstractProgramBasedDynamicTableColumn

from ghidra.util.task import CancelledListener
from ghidra.util.exception import CancelledException

from ghidra.program.model.symbol import SymbolTable, Namespace, SourceType, SymbolType
from ghidra.program.database.symbol import SymbolManager as SymbolMgr
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressSet


demangler = MicrosoftDemangler()
symbolTable = currentProgram.getSymbolTable()
listing = currentProgram.getListing()

userNamespaces = filter( # do/keep this here cause it was freezing Swing thread
    lambda sym: sym.getSymbolType() in {SymbolType.NAMESPACE, SymbolType.CLASS} and not any(sub in sym.getName(False) for sub in {'<', 'DLL', 'switch'}), 
    symbolTable.getDefinedSymbols()
)

def setDemangledLabel(address, mangledString):
    context = demangler.createMangledContext(mangledString, None, None, None)
    demangled = demangler.demangle(context)
    
    demangled.applyTo(currentProgram, address, demangler.createDefaultOptions(), None)
    createLabel(address, mangledString, False, SourceType.ANALYSIS)
    
    printf(getScriptName() + "> Derived: `%s`at %s\n", demangled, address)


def adler32(data):
    MOD_ADLER = 65521
    a = 1
    b = 0

    for byte in data:
        a = (a + ord(byte)) % MOD_ADLER
        b = (b + a) % MOD_ADLER

    return (b << 16) | a


class DecoratedType:
    CTOR =  '0'
    DTOR =  '1'
    # OPERATOR_EQUAL = '4' ghidra seems to fail at demangling these and testing yeilded like only 5 results
    VFTBL = '_7'
    
class AccessType:
    PUBLIC     = 'Q'
    PRIVATE    = 'A'
    PROTECTED  = 'I'
    VPUBLIC    = 'U'
    VPRIVATE   = 'E'
    VPROTECTED = 'M'


def buildSimpleDecoratedName(classNamespace, decoratedType, accessType = ''):    
    scope = ''.join(path + '@' for path in reversed(classNamespace.split(Namespace.DELIMITER)))
        
    if decoratedType == DecoratedType.VFTBL:
        return '??' + decoratedType + scope + '@6B@'
    
    return '??' + decoratedType + scope + '@' + accessType + 'EAA@XZ'


def hashName(decorated):
    return str(adler32(decorated))
    

def deriveSimpleDecoratedNames(namespaces):
    ctors_hash_to_name_map = {}
    dtors_hash_to_name_map = {}
    numDerivedFunctions = 0
    
    vftables_hash_to_name_map = {}
    numDerivedVft = 0
    
    #
    # build hash maps for decorated names
    #
    for namespace in namespaces:
        if '<' in str(namespace) or 'DLL' in str(namespace): # avoid lambda closures, templated classes, and imports
            continue
        
        for accessType in (AccessType.PUBLIC, AccessType.PRIVATE, AccessType.PROTECTED):
            decoratedCTOR = buildSimpleDecoratedName(namespace, DecoratedType.CTOR, accessType)
            ctors_hash_to_name_map[hashName( decoratedCTOR )] = decoratedCTOR
        
        for accessType in (AccessType.PUBLIC, AccessType.VPUBLIC, AccessType.PRIVATE, AccessType.VPRIVATE, AccessType.PROTECTED, AccessType.VPROTECTED):
            decoratedDTOR = buildSimpleDecoratedName(namespace, DecoratedType.DTOR, accessType)
            dtors_hash_to_name_map[hashName( decoratedDTOR )] = decoratedDTOR
        
        decoratedVFTABLE = buildSimpleDecoratedName(namespace, DecoratedType.VFTBL)
        vftables_hash_to_name_map[hashName( decoratedVFTABLE )] = decoratedVFTABLE
    
    #
    # Derive simple constructors and destructors in .text
    #
    codeBlock = getMemoryBlocks()[1]
    for codeAddr in listing.getCommentAddressIterator(AddressSet( codeBlock.getStart(), codeBlock.getEnd() ), True ):
        comment = getPlateComment(codeAddr)
        
        if comment and "Hash" in comment:
            nameHash = comment.split(":")[1].strip()
            name = ctors_hash_to_name_map.get(nameHash) or dtors_hash_to_name_map.get(nameHash)
            if name and name not in [symbol.toString() for symbol in listing.getCodeUnitAt(codeAddr).getSymbols()]:
                createFunction(codeAddr, None)
                setDemangledLabel(codeAddr, name)
                numDerivedFunctions += 1
    #
    # Derive simple vftables .data
    #
    dataBlock = getMemoryBlocks()[2]
    for dataAddr in listing.getCommentAddressIterator( AddressSet( dataBlock.getStart(), dataBlock.getEnd() ), True ):
        comment = getPlateComment(dataAddr)
        
        if comment and "Hash" in comment:
            nameHash = comment.split(":")[1].strip()
            name = vftables_hash_to_name_map.get(nameHash)
            if name and name not in [symbol.toString() for symbol in listing.getDataAt(dataAddr).getSymbols()]:
                setDemangledLabel(dataAddr, name)
                numDerivedVft += 1
    
    totalDerived = numDerivedFunctions + numDerivedVft
    if totalDerived == 0:
        printerr("NO NEW SYMBOLS FOUND")
        return
    
    printf(getScriptName() + "> Found %d function name(s)\n", numDerivedFunctions)
    printf(getScriptName() + "> Found %d vftable name(s)\n", numDerivedVft)
    printf(getScriptName() + "> Derived %d symbol(s)\n", totalDerived)




class NamespacesTableColumn(AbstractProgramBasedDynamicTableColumn):
    def __init__(self):
        super(AbstractProgramBasedDynamicTableColumn, self)

    def getColumnName(self):
        return "Namespaces"

    def getValue(self, rowObject, settings, program, svcProvider):
        return rowObject.getSymbol().getName(True)


class NamespacesTableModel(TransientSymbolTableModel):
    def __init__(self):
        hashSet = HashSet()
        for symbol in userNamespaces:
            hashSet.add(SymbolRowObject(symbol))
        
        super(TransientSymbolTableModel, self).__init__(state.getTool(), currentProgram, hashSet)
    
    def getColumnCount(self):
        return 1
    
    def createTableColumnDescriptor(self):
        descriptor = TableColumnDescriptor()
        descriptor.addVisibleColumn(NamespacesTableColumn())
        return descriptor


class NamespaceSelctionDialog(TableSelectionDialog):
    selectedItems = []
    def __init__(self):
        super(TableSelectionDialog, self).__init__("Select Class Namespace(s)", NamespacesTableModel(), True)



def runDialog():
    tool = state.getTool()
    dialog = NamespaceSelctionDialog()
    tool.showDialog(dialog)
    items = dialog.getSelectionItems()
    if items:
        return [rowObject.getSymbol().getName(True) for rowObject in items]
    
    return None


def askForNamespaces():
    result = [None]

    def promptTask():
        result[0] = runDialog()

    SwingUtilities.invokeAndWait(promptTask)
    return result[0]


#
# ENTRY
#
transaction = currentProgram.startTransaction("Reverse Hashes and Derive Symbols")
try:
    namespaces = askForNamespaces()
    if namespaces:
        deriveSimpleDecoratedNames(namespaces)
finally:
    currentProgram.endTransaction(transaction, True)
