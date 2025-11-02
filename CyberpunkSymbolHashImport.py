#Import symbols from `cyberpunk2077_addresses.json`
#@author Mozz
#@category Cyberpunk
#@keybinding 
#@menupath 
#@toolbar 

import json
import time
from java.io import File
from docking.widgets.filechooser import GhidraFileChooser
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.program.util import GhidraProgramUtilities
from ghidra.program.model.symbol import SourceType, Namespace


analysisMgr = AutoAnalysisManager.getAnalysisManager(currentProgram)

if not GhidraProgramUtilities.isAnalyzed(currentProgram) or analysisMgr.isAnalyzing():
    printerr("Please analyze the program first, exiting")
    exit(1)

expected_file_name = 'cyberpunk2077_addresses.json'
selected_file = File('{}/{}'.format(currentProgram.getExecutablePath().replace(currentProgram.getName(), ''), expected_file_name))

if not selected_file:
    printerr("Could not find '{}', please locate it manually".format(expected_file_name))
    file_chooser = GhidraFileChooser(state.getTool().getActiveComponentProvider().getComponent())
    file_chooser.setSelectedFile(File(currentProgram.getExecutablePath()))
    file_chooser.setTitle("Locate '{}'".format(expected_file_name))

    selected_file = file_chooser.getSelectedFile()

if not selected_file:
    printerr("No file selected, exiting")
    exit(2)
    
if selected_file.getName() != expected_file_name:
    printerr("File selected is not '{}'".format(expected_file_name))
    exit(3)

println("Located '{}'".format(expected_file_name))

# map of CRT builtin functions by their adler32 hash
# specifically those which Ghidra fails to resolve on analysis,
# these are persistent and undecorated by their nature
crtBuiltInMap = {
    608961845: '_aligned_free',
    805111307: '_aligned_malloc',
    250676055: '_fltused',
    105316889: 'fopen',
    69271971: 'free',
    145621625: 'malloc',
    146997900: 'memcpy',
    148374156: 'memset',
    1099040519: 'wWinMainCRTStartup'
}

shouldCommit = False
start() # start transaction
try:
    with open(selected_file.getPath()) as addressessFile:
        println("Parsing...")
        data = json.load(addressessFile)

    for entry in data['Addresses']:
        location = entry['offset'].split(':') # block & block relative offset
        
        block = getMemoryBlocks()[int(location[0])]
        offset = int(location[1], 16)
        
        address = block.getStart().add(offset)
        
        _hash = int(entry['hash'])
        secondary_hash = entry['secondary hash']
        symbol = entry.get('symbol')
        
        comment = "Adler32: {}\nSHA256: {}".format(_hash, secondary_hash)
        setPlateComment(address, comment)
        
        if block.isExecute():
            disassemble(address)
            createFunction(address, symbol)
        
        if symbol: # create namespaces and add symbol if entry has one
            namespaces = symbol.split(Namespace.DELIMITER)
            name = namespaces.pop()

            currentNamespace = currentProgram.getGlobalNamespace()
            for namespace in namespaces:
                currentNamespace = createNamespace(currentNamespace, namespace)
            
            createLabel(address, name, currentNamespace, True, SourceType.IMPORTED)
            println("Imported symbol `{}` at {}".format(symbol, address))

        elif _hash in crtBuiltInMap:
            builtin = crtBuiltInMap[_hash]
            createLabel(address, builtin, True, SourceType.IMPORTED)
            println("Found symbol `{}` at {}".format(builtin, address))
    
    shouldCommit = True
    println("Imports successful!")
    
    if analysisMgr.isAnalyzing():
        println("Awaiting analysis...")
        while analysisMgr.isAnalyzing():
            time.sleep(2)
finally:
    end(shouldCommit) # end transaction

