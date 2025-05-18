# Derive and analyze Cyberpunk RTTI class symbols
#@author Mozz
#@category Symbol
#@keybinding 
#@menupath 
#@toolbar 

import json
from ghidra.program.model.symbol import SymbolTable, Namespace, SourceType
from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.data import DataType, StringDataType, Undefined4DataType
from ghidra.program.util import ProgramLocation
from ghidra.app.util import XReferenceUtils
from ghidra.util.exception import CancelledException

from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader

def fetch(urlStr):
    url = URL(urlStr)
    connection = url.openConnection();
    connection.setRequestMethod("GET");
    connection.connect();
    
    reader = BufferedReader(InputStreamReader(connection.getInputStream()))
    content = []
    line = reader.readLine()
    while line:
        content.append(line)
        line = reader.readLine()
        reader.close()
    connection.disconnect();
    
    return json.loads("\n".join(content))

symbolTable = currentProgram.getSymbolTable()
listing = currentProgram.getListing()

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

def setLabel(address, namespace, name):
    newLabel = createLabel(address, name, namespace, False, SourceType.USER_DEFINED)
    printf(getScriptName() + "> Derived symbol: %s::%s at %s\n", namespace, newLabel, address)


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
    
    return symbolTable.convertNamespaceToClass(currentNamespace)
    
def locateHash(nameHash, addressSet):
    for addr in listing.getCommentAddressIterator(addressSet, True):
        comment = getPlateComment(addr)
        if comment and str(nameHash) in comment:
            return addr
    

def deriveRttiTypeSymbols():
    #
    # Locate rtti::ClassType::ClassType
    #
    classTypeCtor_hash = "3794668520"
    classTypeCtor_addr = None

    printf(getScriptName() + "> Locating `rtti::ClassType::ClassType`(%s)\n", classTypeCtor_hash)
    
    codeBlock = getMemoryBlocks()[1]
    classTypeCtor_addr = locateHash(classTypeCtor_hash, AddressSet( codeBlock.getStart(), codeBlock.getEnd() ))
    
    if classTypeCtor_addr is None:
        printerr("Could not locate rtti::ClassType::ClassType ({}); are hashes imported?".format(classTypeCtor_hash))
        return
    
    printf("Located at %s\n", classTypeCtor_addr)
    createFunction(classTypeCtor_addr, None)
    setLabel(classTypeCtor_addr, createNamespacesFromSymbol('rtti::ClassType'), 'ClassType')

    
    #
    # Iterate through rtti::ClassType::ClassType references to find derived types + generate symbols
    #
    numClasses = 0
    for xref in XReferenceUtils.getAllXrefs(ProgramLocation(currentProgram, classTypeCtor_addr)):
        
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

        symbol = parseSymbol(symbol.replace('"', ''))
        typeNamespace = createNamespacesFromSymbol(symbol)
        
        rttiNamespace = symbolTable.getOrCreateNameSpace(currentProgram.getGlobalNamespace(), 'rtti', SourceType.USER_DEFINED)
        typedClass_name = createClass(rttiNamespace, "TTypedClass<{0}>".format(symbol))
        
        
        currentInstruction = getInstructionAt(xref.getFromAddress())
        for i in range(8):
            currentInstruction = currentInstruction.getNext()
        
            if i == 0:
                classType_vftable = currentInstruction.getReferencesFrom()[0].getToAddress()
                setLabel(classType_vftable, typedClass_name, 'vftable')
            elif i == 2:
                registeredClass_addr = currentInstruction.getReferencesFrom()[0].getToAddress()
                setLabel(registeredClass_addr, typeNamespace, 'registeredClass')
            elif i == 7:
                classDesc_addr = currentInstruction.getReferencesFrom()[0].getToAddress()
                setLabel(classDesc_addr, typeNamespace, 'sm_classDesc')
        
        onConstruct_addr = getReferencesFrom(classType_vftable.add(216))[0].getToAddress()
        if "Dump" not in symbolTable.getPrimarySymbol(onConstruct_addr).toString():
            createFunction(onConstruct_addr, None)
            setLabel(onConstruct_addr, typedClass_name, 'OnConstruct')
        
        
        onDestruct_addr = getReferencesFrom(classType_vftable.add(224))[0].getToAddress()
        if "Dump" not in symbolTable.getPrimarySymbol(onDestruct_addr).toString():
            createFunction(onDestruct_addr, None)
            setLabel(onDestruct_addr, typedClass_name, 'OnDestruct')

        numClasses += 1
    printf(getScriptName() + "> Derived %d RTTI classes\n", numClasses)

#
# Entry
#
transaction = currentProgram.startTransaction("Derive RTTI Class Symbols")
try:
    deriveRttiTypeSymbols()
finally:
    currentProgram.endTransaction(transaction, True)
