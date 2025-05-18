#Import symbols from `cyberpunk2077_addresses.json`
#@author Mozz
#@category Symbol
#@keybinding 
#@menupath 
#@toolbar 

import json
from java.io import File
from docking.widgets.filechooser import GhidraFileChooser
from ghidra.program.model.symbol import SourceType, Namespace
from ghidra.program.model.listing import CodeUnit

symbolTable = currentProgram.getSymbolTable()
programMemory = currentProgram.getMemory()
listing = currentProgram.getListing()

file_chooser = GhidraFileChooser(state.getTool().getActiveComponentProvider().getComponent())
file_chooser.setSelectedFile(File(currentProgram.getExecutablePath()))
file_chooser.setTitle("Select cyberpunk2077_addresses.json")

selected_file = file_chooser.getSelectedFile()

if not selected_file:
    printerr("No file selected, exiting")
    exit()
    
if selected_file.getName() == 'cyberpunk2077_addresses.json':
    transaction = currentProgram.startTransaction("Import Symbols and Add Comments")
    try:
        with open(selected_file.getPath()) as addressessFile:
            data = json.load(addressessFile)

        for entry in data['Addresses']:
            entryHash = entry['hash']
            
            entryOffset = entry['offset'].split(':') # segment & offset(relative to segment)
            
            segment = getMemoryBlocks()[int(entryOffset[0])]
            offset = int(entryOffset[1], 16)
            
            segmentBase = segment.getStart()
            
            address = segmentBase.add(offset)
            
            comment = "Hash: " + entryHash # hash comment
            
            codeUnit = listing.getCodeUnitAt(address)
            if codeUnit:
                setPlateComment(address, comment) # add hash as Plate comment
            
            if 'symbol' in entry: # add symbol if entry has one
                symbol = entry['symbol']
                
                namespaces = symbol.split(Namespace.DELIMITER)
                name = namespaces.pop()
    
                currentNamespace = currentProgram.getGlobalNamespace()
                for namespace in namespaces:
                    currentNamespace = symbolTable.getOrCreateNameSpace(currentNamespace, namespace, SourceType.USER_DEFINED)
                
                createLabel(address, name, currentNamespace, False, SourceType.IMPORTED)
                printf(getScriptName() + "> Imported symbol: `%s` at %s\n", symbol, address)
        println("Succesfully imported hashes!")
    finally:
        currentProgram.endTransaction(transaction, True)
else:
    printerr("File selected is not 'cyberpunk2077_addresses.json'")
