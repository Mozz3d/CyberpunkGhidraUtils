# Derive and analyze Cyberpunk RTTI class symbols
#@author Mozz
#@category Cyberpunk
#@keybinding 
#@menupath 
#@toolbar 

import re

from itertools import combinations

from java.math import BigInteger
from java.security import MessageDigest

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import Namespace, SourceType, RefType

from ghidra.app.util.demangler.microsoft import MicrosoftDemangler, MicrosoftMangledContext, MicrosoftDemanglerOptions

monitor.addCancelledListener(monitor.cancel)
listing = currentProgram.getListing()
demangler = MicrosoftDemangler()
errors = []

hashAddrMapsByBlock = []
for i, block in enumerate(getMemoryBlocks()):
    hashAddrMap = {}
    
    for addr in listing.getCommentAddressIterator( 
        AddressSet(block.getStart(), block.getEnd()), True
    ):
        comment = getPlateComment(addr)
        if comment and "SHA256" in comment:
            match = re.search('[a-f0-9]{64}', comment)
            
            if match:
                hashAddrMap[hex(int(match.group(0), 16))] = addr
 
    hashAddrMapsByBlock.append(hashAddrMap)


def sha256(data):
    digest = MessageDigest.getInstance("SHA-256")
    digest.update(data.encode('utf-8'))
    return hex(int(BigInteger(1, digest.digest()).toString(16).zfill(64), 16))


def setDemangledLabel(address, mangledString):
    try:
        options = demangler.createDefaultOptions()
        options.setApplySignature(False)
        options.setApplyCallingConvention(False)
        context = demangler.createMangledContext(mangledString, options, currentProgram, address)
        demangled = demangler.demangle(context)
        demangled.applyTo(currentProgram, address, options, monitor)
        createLabel(address, mangledString, False, SourceType.ANALYSIS)
        
        println("Derived `{}` at {}".format(demangled, address))
    except java.lang.Exception as e:
        errors.append("Could not apply demangled label '{}' at {}: {}".format(str(demangled).strip(), address, e))

#
# Entry
#
classType_ctor_name = '??0ClassType@rtti@@QEAA@VCName@@II@Z'
classType_ctor_hash = sha256(classType_ctor_name)
classType_ctor_addr = hashAddrMapsByBlock[1].get(classType_ctor_hash)

if classType_ctor_addr is None:
    printerr("Could not locate `rtti::ClassType::ClassType`, are hashes imported?")
    exit(1)

classType_ctor_func = getFunctionAt(classType_ctor_addr)
println("Located `rtti::ClassType::ClassType` at {}".format(classType_ctor_addr))

shouldCommit = False
start() # start transaction
try:
    setDemangledLabel(classType_ctor_addr, classType_ctor_name)
    
    numSymbols = 0
    numFound = 0
    
    for initFunc in classType_ctor_func.getCallingFunctions(monitor):
        conjoinedName = None
        
        for instr in listing.getInstructions(initFunc.getBody(), True):
            ref = instr.getPrimaryReference(1)
            
            if ref is None or ref.getReferenceType() is not RefType.DATA:
                continue
           
            data_addr = ref.getToAddress()
            data = getDataAt(data_addr)
            
            if data is None:
                continue
            
            if not data.isDefined():
                createUnicodeString(data_addr)
                break
            
            if data.hasStringValue():
                conjoinedName = data.getValue()
                break
        
        if conjoinedName is None:
            continue

        qualifiedName = None
        classDesc_mangled = None
        potentialClassDesc_mangled = "?sm_classDesc@{}@@0PEBVClassType@rtti@@EB".format(conjoinedName)
        
        classDesc_addr = hashAddrMapsByBlock[3].get(sha256(potentialClassDesc_mangled))
        
        if classDesc_addr:
            classDesc_mangled = potentialClassDesc_mangled
            qualifiedName = conjoinedName
        else:
            conjoinedName_len = len(conjoinedName)
            maxDelimiters = min(conjoinedName_len // 3, 5)
            
            for numDelimiters in range(1, maxDelimiters + 1):
                for positions in combinations(range(2, conjoinedName_len - 1), numDelimiters):
                    if any(pos2 - pos1 < 2 for pos1, pos2 in zip(positions, positions[1:])):
                        continue
                   
                    parts = []
                    lastPos = 0
                    
                    for pos in positions:
                        parts.append(conjoinedName[lastPos:pos])
                        parts.append(Namespace.DELIMITER)
                        lastPos = pos

                    parts.append(conjoinedName[lastPos:])
                    potentialQualifiedName = ''.join(parts)
                    qualDecorated = '@'.join(reversed(potentialQualifiedName.split(Namespace.DELIMITER)))
                    potentialClassDesc_mangled = "?sm_classDesc@{}@@0PEBVClassType@rtti@@EB".format(qualDecorated)
                    
                    classDesc_addr = hashAddrMapsByBlock[3].get(sha256(potentialClassDesc_mangled))
                    
                    if classDesc_addr:
                        classDesc_mangled = potentialClassDesc_mangled
                        qualifiedName = potentialQualifiedName
                        break
              
                if classDesc_addr:
                    break
        
        if not classDesc_addr:
            errors.append("Could not find 'sm_classDesc' for '{}'".format(conjoinedName))
            continue

        setDemangledLabel(classDesc_addr, classDesc_mangled)
        numSymbols += 1
        numFound += 1
        
        qualifiers = qualifiedName.split(Namespace.DELIMITER)
        qualDecorated = '@'.join(reversed(qualifiers))

        for mangled in (
            "??0{}@@QEAA@XZ".format(qualDecorated)
            , "??0{}@@AEAA@XZ".format(qualDecorated)
            , "??0{}@@IEAA@XZ".format(qualDecorated)
            , "??0{}@@QEAA@AEBV{}@@Z".format(qualDecorated, ''.join(str(i) for i in range(len(qualifiers))))
            , "??1{}@@UEAA@XZ".format(qualDecorated)
            , "??1{}@@QEAA@XZ".format(qualDecorated)
            , "??_G{}@@UEAAPEAXI@Z".format(qualDecorated)
            
            , "??1?$TNativeClassNoCopy@V{}@@@rtti@@UEAA@XZ".format(qualDecorated)
            , "??1?$TNativeClassNoCopy@U{}@@@rtti@@UEAA@XZ".format(qualDecorated)
            , "?OnConstruct@?$TNativeClassNoCopy@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            , "?OnConstruct@?$TNativeClassNoCopy@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            , "?OnDestruct@?$TNativeClassNoCopy@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            , "?OnDestruct@?$TNativeClassNoCopy@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            
            , "??1?$TNativeClass@V{}@@@rtti@@UEAA@XZ".format(qualDecorated)
            , "??1?$TNativeClass@U{}@@@rtti@@UEAA@XZ".format(qualDecorated)
            , "?OnConstruct@?$TNativeClass@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            , "?OnConstruct@?$TNativeClass@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            , "?OnDestruct@?$TNativeClass@V{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            , "?OnDestruct@?$TNativeClass@U{}@@@rtti@@EEBAXPEAX@Z".format(qualDecorated)
            
            , "?RegisterProperties@{}@@SAXPEAVClassType@rtti@@@Z".format(qualDecorated)
            , "?GetNativeClass@{}@@UEBAPEBVClassType@rtti@@XZ".format(qualDecorated)
            , "?GetClass@{}@@UEBAPEBVClassType@rtti@@XZ".format(qualDecorated)
            
            , "?OnPreSave@{}@@UEAAXAEBUPreSaveContext@@@Z".format(qualDecorated)
            , "?OnPostLoad@{}@@UEAAXAEBUPostLoadContext@@@Z".format(qualDecorated)
            , "?OnPropertyPreChange@{}@@UEAA_NAEBVAccessPath@rtti@@AEAV?$SharedStorage@$$CBVValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@@Z".format(qualDecorated)
            , "?OnPropertyPostChange@{}@@UEAAXAEBVAccessPath@rtti@@AEBV?$SharedStorage@VValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@1@Z".format(qualDecorated)
            , "?OnPropertyMissing@{}@@UEAA_NVCName@@AEBVVariant@rtti@@@Z".format(qualDecorated)
            , "?OnPropertyTypeMismatch@{}@@UEAA_NVCName@@PEBVProperty@rtti@@AEBVVariant@4@@Z".format(qualDecorated)
            , "?GetFriendlyName@{}@@UEBA?AVString@red@@XZ".format(qualDecorated)
            , "?GetPath@{}@@UEBA?AVResourcePath@res@@XZ".format(qualDecorated)
        ):
            addr = hashAddrMapsByBlock[1].get(sha256(mangled))
            if addr:
                setDemangledLabel(addr, mangled)
                numSymbols += 1
        
        for mangled in (
            "??_7{}@@6B@".format(qualDecorated)
            , "??_7?$TNativeClassNoCopy@V{}@@@rtti@@6B@".format(qualDecorated)
            , "??_7?$TNativeClassNoCopy@U{}@@@rtti@@6B@".format(qualDecorated)
            , "??_7?$TNativeClass@V{}@@@rtti@@6B@".format(qualDecorated)
            , "??_7?$TNativeClass@U{}@@@rtti@@6B@".format(qualDecorated)
        ):
            addr = hashAddrMapsByBlock[2].get(sha256(mangled))
            if addr:
                setDemangledLabel(addr, mangled)
                numSymbols += 1

    classType_regEventConnector_name = '?Internal_RegisterEventConnector@ClassType@rtti@@QEAAXVCName@@PEBV12@AEBV?$FixedSizeFunction@$$A6AXAEAVISerializable@@AEBV?$THandle@VEvent@red@@@@@Z$0BA@$07@red@@@Z'
    classType_regEventConnector_addr = hashAddrMapsByBlock[1].get(sha256(classType_regEventConnector_name))
    println("Located `rtti::ClassType::Internal_RegisterEventConnector` at {}".format(classType_regEventConnector_addr))
    setDemangledLabel(classType_regEventConnector_addr, classType_regEventConnector_name)

    for regEventConncector_func in getFunctionAt(classType_regEventConnector_addr).getCallingFunctions(monitor):
        eventQualifiedName = None
        
        for instr in listing.getInstructions(regEventConncector_func.getBody(), True):
            ref = instr.getPrimaryReference(1)
            
            if ref is None:
                continue
            
            data = getDataAt(ref.getToAddress())
            if data is None:
                continue
            
            dataSymbol = data.getPrimarySymbol()
            
            if 'sm_classDesc' in dataSymbol.getName():
                eventQualifiedName = str(dataSymbol.getParentNamespace())
     
        if eventQualifiedName is None:
            errors.append("Could not find event class descriptor")
            continue
            
        for regProp_func in regEventConncector_func.getCallingFunctions(monitor):
            typeQualifiedName = str(regProp_func.getParentNamespace())
            
            typeQualifiers = list(reversed(typeQualifiedName.split(Namespace.DELIMITER)))
            eventQualifiers = list(reversed(eventQualifiedName.split(Namespace.DELIMITER)))
            
            templatedEventQualifiers = [
                str(typeQualifiers.index(qual) + 1) if qual in typeQualifiers else qual 
                for qual in eventQualifiers
            ]
            paramEventQualifiers = [
                str(typeQualifiers.index(qual) + 3) if qual in typeQualifiers else qual 
                for qual in eventQualifiers
            ]

            typeQualsDecorated = '@'.join(typeQualifiers)
            templateEventQualsDecorated = '@'.join(templatedEventQualifiers)
            paramEventQualsDecorated = '@'.join(paramEventQualifiers)
            
            addr = None
            
            for mangled in (
                '??$RegisterEventConnector@V{}@@V{}@@rtti@@YAXVCName@@PEAVClassType@0@P8{}@@EAAXAEBV{}@@Z@Z'.format(
                    typeQualsDecorated, templateEventQualsDecorated, typeQualsDecorated, paramEventQualsDecorated
                ),
                '??$RegisterEventConnector@V{}@@U{}@@rtti@@YAXVCName@@PEAVClassType@0@P8{}@@EAAXAEBU{}@@Z@Z'.format(
                    typeQualsDecorated, templateEventQualsDecorated, typeQualsDecorated, paramEventQualsDecorated
                ),
                '??$RegisterEventConnector@U{}@@V{}@@rtti@@YAXVCName@@PEAVClassType@0@P8{}@@EAAXAEBV{}@@Z@Z'.format(
                    typeQualsDecorated, templateEventQualsDecorated, typeQualsDecorated, paramEventQualsDecorated
                ),
                '??$RegisterEventConnector@U{}@@U{}@@rtti@@YAXVCName@@PEAVClassType@0@P8{}@@EAAXAEBU{}@@Z@Z'.format(
                    typeQualsDecorated, templateEventQualsDecorated, typeQualsDecorated, paramEventQualsDecorated
                )
            ):
                addr = hashAddrMapsByBlock[1].get(sha256(mangled))
                if addr:
                    setDemangledLabel(addr, mangled)
                    numSymbols += 1
                    break

            #if addr is None:
            #    addr = regEventConncector_func.getEntryPoint()
            #    #printerr("Could not identify '{}' connector for '{}' at {}".format(eventQualifiedName, typeQualifiedName, addr))
            #    # fallback because there's some other version of RegisterEventConnector I can't figure out
            #    setLabel(addr, getNamespace(None, 'rtti'), 'RegisterEventConnector<{},{}>'.format(typeQualifiedName, eventQualifiedName))
            #    numSymbols += 1  
    for err in errors:
        printerr(err)
    println("Found {} RTTI declared classes".format(numFound))
    println("Derived {} symbols".format(numSymbols))
    shouldCommit = True
finally:
    end(shouldCommit) # end transaction
