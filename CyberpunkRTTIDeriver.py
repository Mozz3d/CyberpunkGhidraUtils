# Derive and analyze Cyberpunk RTTI class symbols
#@author Mozz
#@category Symbol
#@keybinding 
#@menupath 
#@toolbar 

import json

import re

from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.data import DataType, StringDataType, Undefined4DataType
from ghidra.program.model.symbol import SymbolTable, Namespace, SourceType

from ghidra.program.util import ProgramLocation

from ghidra.app.util import XReferenceUtils
from ghidra.app.util.demangler.microsoft import MicrosoftDemangler, MicrosoftMangledContext, MicrosoftDemanglerOptions

from ghidra.util.task import TaskMonitor
from ghidra.util.exception import CancelledException


symbolTable = currentProgram.getSymbolTable()
listing = currentProgram.getListing()
monitor.addCancelledListener(monitor.cancel)
demangler = MicrosoftDemangler()
allNamespaces = {
    "AI": {
        "behavior": {
            "condition": {},
            "event": {},
            "expression": {},
            "task": {},
            "tweak": {}
        },
        "influence": {},
        "squads": {}
    },
    "aiscript": {},
    "anim": {
        "compression": {},
        "fss": {}
    }, 
    "appearance": {}, 
    "at_ui": {},
    "attr": {}, 
    "audio": {
        "breathing": {},
        "ui": {}
    },
    "community": {},
    "cp": {},
    "curve": {},
    "data": {}, 
    "dbg": {
        "Callstack": {}
    },
    "debug": {},
    "device": {}, 
    "effect": {},
    "ent": {
        "dismemberment": {},
        "events": {},
        "ragdoll": {}
    }, 
    "env": {},
    "fx": {},
    "game": {
        "aim": {},
        "audio": {
            "events": {}
        },
        "bb": {},
        "camera": {},
        "carry": {},
        "cheatsystem": {},
        "damage": {},
        "data": {},
        "debug": {},
        "device": {},
        "events": {},
        "gps": {},
        "graph": {},
        "helper": {},
        "hit": {},
        "influence": {},
        "input": {},
        "interactions": { 
            "vis": {}
        },
        "mappins": {},
        "mounting": {},
        "player": {
            "actions": {}
        },
        "projectile": {},
        "smart": {},
        "stateMachine": {
            "event": {},
            "parameterType": {},
            "player": {
                "actions": {}
            }
        },
        "targeting": {},
        "targetingSystem": {},
        "ui": { 
            "arcade": {}
        },
        "watchdog": {},
        "weapon": {
            "events": {}
        }
    }, 
    "garment": {},
    "gen": {},
    "GpuWrapApi": {
        "VertexPacking": {}
    },
    "graph": {},
    "grs": {},
    "gsm": {
        "game": {}
    },
    "ink": {
        "anim": {}
    }, 
    "input": {}, 
    "interop": {}, 
    "itempreview": {},
    "loc": {},
    "localizationPersistence": {},
    "math": {},
    "mappins": {},
    "mesh": {
        "ui": {}
    },
    "minimap": {
        "ui": {}
    },
    "move": {},
    "mp": {},
    "nav": {
        "gendebug": {}
    }, 
    "net": {},
    "oauth": {},
    "physics": {
        "cloth": {}
    }, 
    "population": {},
    "prv": {},
    "puppetpreview": {},
    "quest": {
        "dbg": {},
        "vehicle": {}
    }, 
    "red": {}, 
    "rend": {
        "dim": {}
    }, 
    "res": {},
    "save": {},
    "scn": {
        "dev": {},
        "events": {},
        "fpp": {},
        "loc": {},
        "prv": {},
        "screenplay": {},
        "sim": {}
    },
    "script": {},
    "sense": {},
    "services": {},
    "shadows": {},
    "shared": {},
    "tempshit": {},
    "text": {},
    "tick": {},
    "tools": {},
    "user": {},
    "ui": {}, 
    "vehicle": {}, 
    "vg": {},
    "vis": {},
    "work": {
        "workspot": {}
    },
    "world": {
        "geometry": {
            "average": {}
        },
        "ui": {}
    }
}
hashAddrBlocks = []
for i, block in enumerate(getMemoryBlocks()):
    hashAddrMap = {}
    for addr in listing.getCommentAddressIterator( AddressSet( block.getStart(), block.getEnd() ), True):
        comment = getPlateComment(addr)
        if comment and "Hash" in comment:
            match = re.search(r'Hash: (\d+)', comment)
            if match:
                _hash = int(match.group(1))
                hashAddrMap[_hash] = addr
    hashAddrBlocks.insert(i, hashAddrMap)


def setLabel(address, namespace, name):
    newLabel = createLabel(address, name, namespace, False, SourceType.USER_DEFINED)
    printf(getScriptName() + "> Derived symbol: %s::%s at %s\n", namespace, newLabel, address)


def setDemangledLabel(address, mangledString):
    options = demangler.createDefaultOptions()
    options.setApplySignature(False)
    options.setApplyCallingConvention(False)
    context = demangler.createMangledContext(mangledString, options, currentProgram, address)
    demangled = demangler.demangle(context)
    demangled.applyTo(currentProgram, address, options, monitor)
    
    createLabel(address, mangledString, False, SourceType.ANALYSIS)
    
    printf(getScriptName() + "> Derived: `%s`at %s\n", demangled, address)


def parseSymbol(conjoinedSymbol):
    name = conjoinedSymbol
    namespacing = ''
    currentNamespace = allNamespaces
    
    hasMatch = True
    while hasMatch and currentNamespace:
        hasMatch = False
        
        for namespace in sorted(currentNamespace, key=len, reverse=True):
        
            if name.startswith(namespace):
                namespacing += namespace + Namespace.DELIMITER
                name = name[len(namespace):]
                currentNamespace = currentNamespace[namespace]
                
                hasMatch = True
                break
                
        if not hasMatch:
            break
    
    return namespacing + name


def createNamespacesFromSymbol(symbol):
    namespaces = symbol.split(Namespace.DELIMITER)
    
    currentNamespace = currentProgram.getGlobalNamespace()
    for namespace in namespaces:
        currentNamespace = symbolTable.getOrCreateNameSpace(currentNamespace, namespace, SourceType.USER_DEFINED)
    
    return currentNamespace


def adler32(data):
    MOD_ADLER = 65521
    a = 1
    b = 0

    for byte in data:
        a = (a + ord(byte)) % MOD_ADLER
        b = (b + a) % MOD_ADLER

    return (b << 16) | a


def locateClassTypeConstructor():
    ctorHash = 3794668520
    
    printf(getScriptName() + "> Locating `rtti::ClassType::ClassType`(%s)\n", ctorHash)
    addr = hashAddrBlocks[1].get(ctorHash)
    if addr:
        printf(getScriptName() + "> Located `rtti::ClassType::ClassType`(%s) at %s\n", ctorHash, addr)
        createFunction(addr, None)
        setLabel(addr, createNamespacesFromSymbol('rtti::ClassType'), 'ClassType')
        return addr
    
  
    printerr("Could not locate rtti::ClassType::ClassType ({}); are hashes imported?".format(ctorHash))
    return


def mangleClassTypeFuncs(typenameStr):
    qualDecorated = '@'.join(reversed(typenameStr.split(Namespace.DELIMITER)))
    return [
        "??0{}@@QEAA@XZ".format(qualDecorated),
        "??0{}@@AEAA@XZ".format(qualDecorated),
        "??0{}@@IEAA@XZ".format(qualDecorated),
        "??_G{}@@UEAAPEAXI@Z".format(qualDecorated),
        "??1{}@@UEAA@XZ".format(qualDecorated),
        "??1{}@@QEAA@XZ".format(qualDecorated),
        "?RegisterProperties@{}@@SAXPEAVClassType@rtti@@@Z".format(qualDecorated)
    ]


def mangleClassTypeVFT(typenameStr):
    qualDecorated = '@'.join(reversed(typenameStr.split(Namespace.DELIMITER)))
    return [
        "??_7{}@@6B@".format(qualDecorated)
    ]


def mangleClassTypeData(typenameStr):
    qualDecorated = '@'.join(reversed(typenameStr.split(Namespace.DELIMITER)))
    return [
        "?sm_classDesc@{}@@0PEBVClassType@rtti@@EB".format(qualDecorated)
    ]


def mangleRTTINativeTypeNoCopyFuncs(wrappedTypenameStr):
    qualDecorated = '@'.join(reversed(wrappedTypenameStr.split(Namespace.DELIMITER)))
    return [
        "??1?$TNativeClassNoCopy@V{}@@@rtti@@UEAA@XZ".format(qualDecorated),
        "??1?$TNativeClassNoCopy@U{}@@@rtti@@UEAA@XZ".format(qualDecorated),
        "?OnConstruct@?$TNativeClassNoCopy@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated),
        "?OnDestruct@?$TNativeClassNoCopy@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated),
        "?OnConstruct@?$TNativeClassNoCopy@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated),
        "?OnDestruct@?$TNativeClassNoCopy@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
    ]


def mangleRTTINativeTypeNoCopyVFT(wrappedTypenameStr):
    qualDecorated = '@'.join(reversed(wrappedTypenameStr.split(Namespace.DELIMITER)))
    return [
        "??_7?$TNativeClassNoCopy@V{}@@@rtti@@6B@".format(qualDecorated),
        "??_7?$TNativeClassNoCopy@U{}@@@rtti@@6B@".format(qualDecorated)
    ]
        

def mangleRTTINativeTypeFuncs(wrappedTypenameStr):
    qualDecorated = '@'.join(reversed(wrappedTypenameStr.split(Namespace.DELIMITER)))
    return [
        "??1?$TNativeClass@V{}@@@rtti@@UEAA@XZ".format(qualDecorated),
        "??1?$TNativeClass@U{}@@@rtti@@UEAA@XZ".format(qualDecorated),
        "?OnConstruct@?$TNativeClass@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated),
        "?OnDestruct@?$TNativeClass@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated),
        "?OnConstruct@?$TNativeClass@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated),
        "?OnDestruct@?$TNativeClass@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
    ]

def mangleRTTINativeTypeVFT(wrappedTypenameStr):
    qualDecorated = '@'.join(reversed(wrappedTypenameStr.split(Namespace.DELIMITER)))
    return [
        "??_7?$TNativeClass@V{}@@@rtti@@6B@".format(qualDecorated),
        "??_7?$TNativeClass@U{}@@@rtti@@6B@".format(qualDecorated)
    ]


def mangleRTTITypeFuncs(typenameStr):
    return mangleRTTINativeTypeNoCopyFuncs(typenameStr) + mangleRTTINativeTypeFuncs(typenameStr) + mangleClassTypeFuncs(typenameStr)


def mangleRTTITypeVFTs(typenameStr):
    return mangleRTTINativeTypeNoCopyVFT(typenameStr) + mangleRTTINativeTypeVFT(typenameStr) + mangleClassTypeVFT(typenameStr)


def mangleRTTITypeData(typenameStr):
    return mangleClassTypeData(typenameStr)
    
#
# Entry
#
shouldCommit = False
transaction = currentProgram.startTransaction("Derive RTTI Class Symbols")
try:
    numClasses = 0
    numSymbols = 0
    
    for xref in XReferenceUtils.getAllXrefs(ProgramLocation(currentProgram, locateClassTypeConstructor())):
        monitor.checkCanceled()
        
        currentInstruction = getInstructionAt(xref.getFromAddress())
        if currentInstruction is None:
            continue

        while currentInstruction:
            if all(mnemonic in str(currentInstruction) for mnemonic in ("LEA", "RDX")):
                refs = currentInstruction.getReferencesFrom()
                if len(refs) == 1:
                    break
            currentInstruction = currentInstruction.getPrevious()

        symbol = None
        symbol_addr = currentInstruction.getReferencesFrom()[0].getToAddress()
        
        if symbol_addr and symbol_addr.isMemoryAddress():
            data = getDataAt(symbol_addr)
            if not data:
                data = createAsciiString(symbol_addr)
            
            symbol = data.getDefaultValueRepresentation() if data else None

        if symbol is None:
            continue
        
        qualifiedSymbol = parseSymbol(symbol.replace('"', ''))
        
        
        funcsHashMap = {adler32(mangled): mangled for mangled in mangleRTTITypeFuncs(qualifiedSymbol)}
        for _hash in funcsHashMap.keys():
            addr = hashAddrBlocks[1].get(_hash)
            if addr:
                setDemangledLabel(addr, funcsHashMap[_hash])
                numSymbols += 1
        
        rdataHashMap = {adler32(mangled): mangled for mangled in mangleRTTITypeVFTs(qualifiedSymbol)}
        for _hash in rdataHashMap.keys():
            addr = hashAddrBlocks[2].get(_hash)
            if addr:
                setDemangledLabel(addr, rdataHashMap[_hash])
                numSymbols += 1
        
        dataHashMap = {adler32(mangled): mangled for mangled in mangleRTTITypeData(qualifiedSymbol)}
        for _hash in dataHashMap.keys():
            addr = hashAddrBlocks[3].get(_hash)
            if addr:
                setDemangledLabel(addr, dataHashMap[_hash])
                numSymbols += 1
        
        
        # hack for finding `registeredClass` because I can't figure out it's mangling
        currentInstruction = getInstructionAt(xref.getFromAddress()).getNext().getNext().getNext()
        registeredClass_addr = currentInstruction.getReferencesFrom()[0].getToAddress()
        if registeredClass_addr:
            setLabel(registeredClass_addr, createNamespacesFromSymbol(qualifiedSymbol), 'registeredClass')
            numSymbols += 1

        numClasses += 1

    printf(getScriptName() + "> Found %d RTTI classes\n", numClasses)
    printf(getScriptName() + "> Derived %d symbols\n", numSymbols)
    shouldCommit = True
finally:
    currentProgram.endTransaction(transaction, shouldCommit)
