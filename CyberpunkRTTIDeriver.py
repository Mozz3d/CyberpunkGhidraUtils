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

listing = currentProgram.getListing()

demangler = MicrosoftDemangler()
demanglerOptions = demangler.createDefaultOptions()
demanglerOptions.setApplySignature(False)
demanglerOptions.setApplyCallingConvention(False)
demanglerOptions.setDoDisassembly(True)

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
        context = demangler.createMangledContext(mangledString, demanglerOptions, currentProgram, address)
        demangled = demangler.demangle(context)
        demangled.applyTo(currentProgram, address, demanglerOptions, monitor)
        createLabel(address, mangledString, False, SourceType.ANALYSIS)
        
        println("Derived `{}` at {}".format(demangled, address))
    except Exception as e:
        errors.append("Could not apply demangled label '{}' at {}: {}".format(str(demangled).strip(), address, e))

#
# Entry
#
classType_ctor_name = '??0ClassType@rtti@@QEAA@VCName@@II@Z'
classType_ctor_hash = '0xa29fc63b1039a75263e240ff523794a6009bc800af888f648d2f1c3b1f1b9855'
classType_ctor_addr = hashAddrMapsByBlock[1].get(classType_ctor_hash)

if classType_ctor_addr is None:
    raise ("Could not locate `rtti::ClassType::ClassType`, are hashes imported?")

classType_ctor_func = getFunctionAt(classType_ctor_addr)
println("Located `rtti::ClassType::ClassType` at {}".format(classType_ctor_addr))

shouldCommit = False
start() # start transaction
try:
    setDemangledLabel(classType_ctor_addr, classType_ctor_name)
    
    numSymbols = 0
    numFound = 0
    
    qualifiedNames = ["CName", "DataBuffer", "red::String", "serialization::DeferredDataBuffer"]
    
    for initFunc in classType_ctor_func.getCallingFunctions(monitor):
        conjoinedName = None
        
        for instr in listing.getInstructions(initFunc.getBody(), True):
            ref = instr.getPrimaryReference(1)
            
            if ref is None or ref.getReferenceType() != RefType.DATA:
                continue
           
            data_addr = ref.getToAddress()
            data = getDataAt(data_addr)
            
            if data is None:
                continue
            
            if not data.isDefined():
                createUnicodeString(data_addr)
                data = getDataAt(data_addr)
            
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
        qualifiedNames.append(qualifiedName)

    for qualifiedName in qualifiedNames:
        qualifiers = qualifiedName.split(Namespace.DELIMITER)
        qualDecorated = '@'.join(reversed(qualifiers))
        backRefs = ''.join(str(i) for i in range(len(qualifiers)))
        classKey = 'V'
        
        # use native type vftable resolution to identify class key
        for mangled, key in (
            ("??_7?$TNativeClassNoCopy@V{}@@@rtti@@6B@".format(qualDecorated), 'V')
            , ("??_7?$TNativeClassNoCopy@U{}@@@rtti@@6B@".format(qualDecorated), 'U')
            , ("??_7?$TNativeClass@V{}@@@rtti@@6B@".format(qualDecorated), 'V')
            , ("??_7?$TNativeClass@U{}@@@rtti@@6B@".format(qualDecorated), 'U')
            , ("?theName@?1??GetTypeName@?$TTypeName@V{}@@@@SA?BVCName@@XZ@4V3@A".format(qualDecorated), 'V')
            , ("?theName@?1??GetTypeName@?$TTypeName@U{}@@@@SA?BVCName@@XZ@4V3@A".format(qualDecorated), 'U')
        ):
            addr = hashAddrMapsByBlock[2].get(sha256(mangled))
            if addr:
                setDemangledLabel(addr, mangled)
                numSymbols += 1
                classKey = key
        
        for mangled in (
            "??0{}@@QEAA@XZ".format(qualDecorated)
            , "??0{}@@AEAA@XZ".format(qualDecorated)
            , "??0{}@@IEAA@XZ".format(qualDecorated)
            , "??0{}@@QEAA@AEB{}{}@@Z".format(qualDecorated, classKey, backRefs)
            , "??0{}@@QEAA@$$QEA{}{}@@Z".format(qualDecorated, classKey, backRefs)
            , "??1{}@@UEAA@XZ".format(qualDecorated)
            , "??1{}@@QEAA@XZ".format(qualDecorated)
            , "??1?$DynArray@{}{}@@@red@@QEAA@XZ".format(classKey, qualDecorated)
            , "??4{}@@QEAAAEA{}{}@AEB{}{}@@Z".format(qualDecorated, classKey, backRefs, classKey, backRefs)
            , "??4{}@@QEAAAEA{}{}@$$QEA{}{}@@Z".format(qualDecorated, classKey, backRefs, classKey, backRefs)
            , "??8{}@@QEBA_NAEB{}{}@@Z".format(qualDecorated, classKey, backRefs)
            , "??9{}@@QEBA_NAEB{}{}@@Z".format(qualDecorated, classKey, backRefs)
            , "??Y{}@@QEAAAEA{}{}@AEB{}{}@@Z".format(qualDecorated, classKey, backRefs, classKey, backRefs)
            , "??_G{}@@UEAAPEAXI@Z".format(qualDecorated)
            
            , "??1?$TNativeClassNoCopy@{}{}@@@rtti@@UEAA@XZ".format(classKey, qualDecorated)
            , "?OnConstruct@?$TNativeClassNoCopy@{}{}@@@rtti@@EEBAXPEAX@Z".format(classKey, qualDecorated)
            , "?OnDestruct@?$TNativeClassNoCopy@{}{}@@@rtti@@EEBAXPEAX@Z".format(classKey, qualDecorated)
            
            , "??1?$TNativeClass@{}{}@@@rtti@@UEAA@XZ".format(classKey, qualDecorated)
            , "?OnConstruct@?$TNativeClass@{}{}@@@rtti@@EEBAXPEAX@Z".format(classKey, qualDecorated)
            , "?OnDestruct@?$TNativeClass@{}{}@@@rtti@@EEBAXPEAX@Z".format(classKey, qualDecorated)
            
            , "?RegisterProperties@{}@@SAXPEAVClassType@rtti@@@Z".format(qualDecorated)
            , "?GetNativeClass@{}@@UEBAPEBVClassType@rtti@@XZ".format(qualDecorated)
            , "?GetClass@{}@@UEBAPEBVClassType@rtti@@XZ".format(qualDecorated)
            , "?GetMemoryPool@{}@@UEBAAEBVPool@memory@red@@XZ".format(qualDecorated)
            , "??$GetNativeTypeHash@{}{}@@@@YA_KXZ".format(classKey, qualDecorated)
            
            , "??$ResolveRttiType@{}{}@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$THandle@{}{}@@@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$WeakHandle@{}{}@@@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$TResRef@{}{}@@@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$TResAsyncRef@{}{}@@@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$DynArray@{}{}@@@red@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$DynArray@V?$THandle@{}{}@@@@@red@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$DynArray@V?$TResRef@{}{}@@@@@red@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            , "??$ResolveRttiType@V?$DynArray@V?$TResAsyncRef@{}{}@@@@@red@@@@YAPEBVIType@rtti@@XZ".format(classKey, qualDecorated)
            
            , "?OnPreSave@{}@@UEAAXAEBUPreSaveContext@@@Z".format(qualDecorated)
            , "?OnPostLoad@{}@@UEAAXAEBUPostLoadContext@@@Z".format(qualDecorated)
            , "?OnPropertyPreChange@{}@@UEAA_NAEBVAccessPath@rtti@@AEAV?$SharedStorage@$$CBVValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@@Z".format(qualDecorated)
            , "?OnPropertyPostChange@{}@@UEAAXAEBVAccessPath@rtti@@AEBV?$SharedStorage@VValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@1@Z".format(qualDecorated)
            , "?OnSerialize@{}@@EEAAXAEAVIFile@@@Z".format(qualDecorated)
            , "?OnPropertyMissing@{}@@UEAA_NVCName@@AEBVVariant@rtti@@@Z".format(qualDecorated)
            , "?OnPropertyTypeMismatch@{}@@UEAA_NVCName@@PEBVProperty@rtti@@AEBVVariant@4@@Z".format(qualDecorated)
            , "?GetFriendlyName@{}@@UEBA?AVString@red@@XZ".format(qualDecorated)
            , "?GetPath@{}@@UEBA?AVResourcePath@res@@XZ".format(qualDecorated)
        ):
            addr = hashAddrMapsByBlock[1].get(sha256(mangled))
            if addr:
                setDemangledLabel(addr, mangled)
                numSymbols += 1
        
        vftable_mangled = "??_7{}@@6B@".format(qualDecorated)
        vftable_addr = hashAddrMapsByBlock[2].get(sha256(vftable_mangled))
        if vftable_addr:
            setDemangledLabel(vftable_addr, vftable_mangled)
            numSymbols += 1
        
        nativeTypeHash_mangled = "?nativeTypeHash@?1???$GetNativeTypeHash@{}{}@@@@YA_KXZ@4IA".format(classKey, qualDecorated)
        nativeTypeHash_addr = hashAddrMapsByBlock[3].get(sha256(nativeTypeHash_mangled))
        if nativeTypeHash_addr:
            setDemangledLabel(nativeTypeHash_addr, nativeTypeHash_mangled)
            numSymbols += 1
    
    for mangledFundamental in ('C', 'D', 'E', 'F', 'G', 'H', 'I', 'M', 'N', '_J', '_K', '_N'):
        for mangled in (
            "??$ResolveRttiType@{}@@YAPEBVIType@rtti@@XZ".format(mangledFundamental)
            , "??$ResolveRttiType@V?$DynArray@{}@red@@@@YAPEBVIType@rtti@@XZ".format(mangledFundamental)
        ):
            addr = hashAddrMapsByBlock[1].get(sha256(mangled))
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
