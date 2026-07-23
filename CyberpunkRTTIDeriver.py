# Derive and analyze Cyberpunk RTTI class symbols
#@author Mozz
#@category Cyberpunk
#@keybinding 
#@menupath 
#@toolbar 

import hashlib
import multiprocessing
import os
import re
import sys
import tempfile
import zlib

from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from itertools import combinations, chain

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import Namespace, SourceType, RefType

from ghidra.app.util.demangler.microsoft import (
    MicrosoftDemangler,
    MicrosoftMangledContext,
    MicrosoftDemanglerOptions,
)

current_program = currentProgram
listing = current_program.getListing()
errors = []
found_classes = []
num_derived = 0


def quitIfCancelled():
    if monitor.isCancelled():
        quit()

class demangling:
    ms = MicrosoftDemangler()
    options = ms.createDefaultOptions()

    @staticmethod
    def demangle(mangled):
        return demangling.ms.demangle(
            demangling.ms.createMangledContext(mangled, demangling.options, current_program, None)
        )
    
    @staticmethod
    def label(addr, mangled):
        global num_derived
        demangled = demangling.demangle(mangled)
        try:
            ns = demangled.createNamespace(current_program, demangled.getNamespace(), None, True)
            createLabel(addr, demangled.getName(), ns, True, SourceType.ANALYSIS)
            createLabel(addr, demangled.getMangledString(), False, SourceType.ANALYSIS)
            # for whatever reason, setting and getting plate comments is exceedingly slow...
            # so much so that the script takes extrememly long when attempting to do so.
            # maybe find a fix?
            # setPlateComment(addr, f"{getPlateComment(addr)}\n{str(demangled).strip()}\n")
            num_derived += 1
            println(f"Derived `{str(demangled).strip()}` at {addr}")
        except Exception as e:
            errors.append(f"Could not apply label '{str(demangled).strip()}' at {addr}: {e}")


class hashing:
    @staticmethod
    def adler32(data_bytes):
        return int(zlib.adler32(data_bytes))

    @staticmethod
    def sha256(data_bytes):
        return int.from_bytes(hashlib.sha256(data_bytes).digest(), 'big')


class resolving:
    seen_strings = set()
    seen_namespaces = set()

    _ADLER32_RE = re.compile(r'Adler32: (\b\d+\b)')
    _SHA256_RE  = re.compile(r'SHA256: ([a-f0-9]{64})')

    adler32_hashes = set()
    block_sha256_maps = []

    @staticmethod
    def getHashesAt(addr):
        comment = getPlateComment(addr)
        if not comment:
            return (), ()
        a32s    = (int(m)     for m in resolving._ADLER32_RE.findall(comment))
        sha256s = (int(m, 16) for m in resolving._SHA256_RE.findall(comment))
        return a32s, sha256s

    @staticmethod
    def findMangled(mangled, block_idx=1):
        mangled_encoded = mangled.encode('utf-8')
        if hashing.adler32(mangled_encoded) in resolving.adler32_hashes:
            return resolving.block_sha256_maps[block_idx].get(hashing.sha256(mangled_encoded))
    
    @staticmethod
    def findMangledThenLabel(mangled, block_idx):
        if addr := resolving.findMangled(mangled, block_idx):
            demangling.label(addr, mangled)
            return addr
    
    @staticmethod
    def generateQualifiers(conjoined_name):
        name_len = len(conjoined_name)
        max_delimiters = min(name_len // 3, 5)

        start_pos = 2
        for namespace in sorted(resolving.seen_namespaces, key=len):
            if conjoined_name.startswith(namespace):
                start_pos = len(namespace)
                break

        for num_delimiters in range(max_delimiters + 1):
            max_compressed_pos = name_len - num_delimiters
            for compressed_positions in combinations(range(start_pos, max_compressed_pos + 1), num_delimiters):
                # expand into gap of at least 2 characters
                positions = (compressed_pos + idx for idx, compressed_pos in enumerate(compressed_positions))
                qualifiers = []
                last_pos = 0
                for pos in positions:
                    qualifiers.append(conjoined_name[last_pos:pos])
                    last_pos = pos
                qualifiers.append(conjoined_name[last_pos:])
                yield qualifiers

    @staticmethod
    def resolveClassTypes():
        if not hasattr(resolving.resolveClassTypes, 'class_type_ctor_func'):
            class_type_ctor_mangled = '??0ClassType@rtti@@QEAA@VCName@@II@Z'
            if addr := resolving.findMangledThenLabel(class_type_ctor_mangled, 1):
                resolving.resolveClassTypes.class_type_ctor_func = getFunctionAt(addr)
                println(f"Located `rtti::ClassType::ClassType` at {addr}")
            else:
                raise RuntimeError("Could not locate `rtti::ClassType::ClassType`, are hashes imported?")

        class_type_ctor_func = resolving.resolveClassTypes.class_type_ctor_func
        for init_func in class_type_ctor_func.getCallingFunctions(monitor):
            conjoined_name = None
            for instr in listing.getInstructions(init_func.getBody(), True):
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
                    conjoined_name = data.getValue()
                    break

            if conjoined_name is None:
                continue

            for potential_quals in resolving.generateQualifiers(conjoined_name):
                quals = tuple(reversed(potential_quals))
                decorated = '@'.join(quals)
                for mangled, cls_key in (
                    (f"?nativeTypeHash@?1???$GetNativeTypeHash@V{decorated}@@@@YA_KXZ@4IA", 'V'),
                    (f"?nativeTypeHash@?1???$GetNativeTypeHash@U{decorated}@@@@YA_KXZ@4IA", 'U'),
                ):
                    if addr := resolving.findMangled(mangled, 3):
                        if len(potential_quals) > 1 and (qual := potential_quals[0]) and len(qual) > 2:
                            resolving.seen_namespaces.add(qual)
                        yield cls_key, quals, addr, mangled
                        break
                else:
                    continue
                break

    @staticmethod
    def resolveUniqueTypes():
        for name in (
            "Box",
            "CName",
            "DataBuffer",
            "DeferredDataBuffer@serialization",
            "EulerAngles",
            "QsTransform",
            "Quaternion",
            "String@red",
            "TweakDBID@data@game",
            "Vector2",
            "Vector3",
            "Vector4",
        ):
            for mangled, cls_key in (
                (f"?nativeTypeHash@?1???$GetNativeTypeHash@V{name}@@@@YA_KXZ@4IA", 'V'),
                (f"?nativeTypeHash@?1???$GetNativeTypeHash@U{name}@@@@YA_KXZ@4IA", 'U'),
            ):
                if native_type_hash_addr := resolving.findMangled(mangled, 3):
                    yield cls_key, tuple(name.split('@')), native_type_hash_addr, mangled
                    break

#
#
# Entry
#
#
println(f"Building hash-address maps...")
for block in getMemoryBlocks():
    sha256_map = {}
    for addr in listing.getCommentAddressIterator(AddressSet(block.getStart(), block.getEnd()), True):
        quitIfCancelled()
        a32_hashes, sha256_hashes = resolving.getHashesAt(addr)
        resolving.adler32_hashes.update(a32_hashes)
        for sha256 in sha256_hashes:
            sha256_map[sha256] = addr
    resolving.block_sha256_maps.append(sha256_map)

should_commit = False
start()  # start transaction
try:
    current_program.setEventsEnabled(False) # prevents event thrashing lag
    
    for cls_key, quals, native_type_hash_addr, native_type_hash_mangled in chain(
        resolving.resolveClassTypes(),
        resolving.resolveUniqueTypes(),
    ):
        quitIfCancelled()
        decorated = '@'.join(quals)
        demangling.label(native_type_hash_addr, native_type_hash_mangled)

        copy_spec = ''
        cls_key_and_decorated = f"{cls_key}{decorated}"
        cls_key_and_back_refs = f"{cls_key}{'0123456789'[:len(quals)]}"
        
        found_classes.append((
            cls_key.encode('utf-8'),
            decorated.encode('utf-8'),
            tuple(qual.encode('utf-8') for qual in quals),
            cls_key_and_decorated.encode('utf-8'),
        ))
        
        
        for mangled, is_no_copy in (
            (f"??_7?$TNativeClass@{cls_key_and_decorated}@@@rtti@@6B@",       False),
            (f"??_7?$TNativeClassNoCopy@{cls_key_and_decorated}@@@rtti@@6B@", True),
        ):
            if resolving.findMangledThenLabel(mangled, 2):
                if is_no_copy:
                    copy_spec = 'NoCopy'
                break
        
        for mangled in (
            f"??0{decorated}@@QEAA@XZ",
            f"??0{decorated}@@AEAA@XZ",
            f"??0{decorated}@@IEAA@XZ",
            f"??0{decorated}@@QEAA@AEB{cls_key_and_back_refs}@@Z",
            f"??0{decorated}@@QEAA@$$QEA{cls_key_and_back_refs}@@Z",
            f"??0?$THandle@{cls_key_and_decorated}@@@@QEAA@XZ",
            f"??0?$WeakHandle@{cls_key_and_decorated}@@@@QEAA@XZ",
            f"??1{decorated}@@UEAA@XZ",
            f"??1{decorated}@@QEAA@XZ",
            f"??1?$DynArray@{cls_key_and_decorated}@@@red@@QEAA@XZ",
            f"??1?$THandle@{cls_key_and_decorated}@@@@QEAA@XZ",
            f"??1?$WeakHandle@{cls_key_and_decorated}@@@@QEAA@XZ",
            f"??4{decorated}@@QEAAAEA{cls_key_and_back_refs}@AEB{cls_key_and_back_refs}@@Z",
            f"??4{decorated}@@QEAAAEB{cls_key_and_back_refs}@AEB{cls_key_and_back_refs}@@Z",
            f"??4{decorated}@@QEAAAEA{cls_key_and_back_refs}@$$QEA{cls_key_and_back_refs}@@Z",
            f"??4?$DynArray@{cls_key_and_decorated}@@@red@@QEAAAEAV01@AEBV01@@Z",
            f"??4?$DynArray@{cls_key_and_decorated}@@@red@@QEAAAEAV01@$$QEAV01@@Z",
            f"??4?$THandle@{cls_key_and_decorated}@@@@QEAAAEAV0@AEBV0@@Z",
            f"??4?$THandle@{cls_key_and_decorated}@@@@QEAAAEAV0@$$QEAV0@@Z",
            f"??8{decorated}@@QEBA_NAEB{cls_key_and_back_refs}@@Z",
            f"??9{decorated}@@QEBA_NAEB{cls_key_and_back_refs}@@Z",
            f"??Y{decorated}@@QEAAAEA{cls_key_and_back_refs}@AEB{cls_key_and_back_refs}@@Z",
            f"??_G{decorated}@@UEAAPEAXI@Z",
            
            f"??1?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@UEAA@XZ",
            f"??_G?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@UEAAPEAXI@Z",
            f"?Copy@?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@EEBAXPEAXPEBX@Z",
            f"?OnConstruct@?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@EEBAXPEAX@Z",
            f"?OnDestruct@?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@EEBAXPEAX@Z",
            
            f"??$IsA@{cls_key_and_decorated}@@@ClassType@rtti@@QEBA_NXZ",
            f"??$CreateObject@{cls_key_and_decorated}@@@ClassType@rtti@@QEBAPEA{cls_key_and_decorated}@@XZ",
            f"??$CreateHandle@{cls_key_and_decorated}@@$$V@@YA?AV?$THandle@{cls_key_and_decorated}@@@@XZ",
            f"??$CreateUniquePtr@{cls_key_and_decorated}@@$$V@red@@YA?AV?$UniquePtr@{cls_key_and_decorated}@@VDefaultUniquePtrDestructor@memory@red@@@0@XZ",
            
            f"??$GetTypeObject@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ",
            f"??$GetTypeObject@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$GetTypeObject@V?$THandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$GetTypeObject@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            
            f"?GetNativeClass@{decorated}@@UEBAPEBVClassType@rtti@@XZ",
            f"?GetClass@{decorated}@@UEBAPEBVClassType@rtti@@XZ",
            f"?GetFriendlyName@{decorated}@@UEBA?AVString@red@@XZ",
            f"?GetFriendlyDescription@{decorated}@@UEBAPEBDXZ",
            f"?GetDescription@{decorated}@@UEBA?AVString@red@@XZ",
            f"?RegisterProperties@{decorated}@@SAXPEAVClassType@rtti@@@Z",
            
            f"??$GetNativeTypeHash@{cls_key_and_decorated}@@@@YA_KXZ",
            f"??$GetNativeTypeHash@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YA_KXZ",
            f"??$GetNativeTypeHash@V?$DynArray@V?$THandle@{cls_key_and_decorated}@@@@@red@@@@YA_KXZ",
            f"??$GetNativeTypeHash@V?$THandle@{cls_key_and_decorated}@@@@@@YA_KXZ",
            f"??$GetNativeTypeHash@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YA_KXZ",
            
            f"??$ResolveRttiType@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$THandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$TResRef@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$TResAsyncRef@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$THandle@{cls_key_and_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$WeakHandle@{cls_key_and_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$TResRef@{cls_key_and_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$TResAsyncRef@{cls_key_and_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",

            f"?GetMemoryPool@{decorated}@@UEBAAEBVPool@memory@red@@XZ",

            f"??_G?$DataUpdater@{cls_key_and_decorated}@@@TweakDB@data@game@@UEAAPEAXI@Z",
            
            f"?Clear@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAXXZ",
            f"?Empty@?$DynArray@{cls_key_and_decorated}@@@red@@QEBA_NXZ",
            f"?PushBack@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAXAEB{cls_key_and_decorated}@@@Z",
            f"?PushBack@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAX$$QEA{cls_key_and_decorated}@@@Z",
            f"?Reserve@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAXI@Z",
            f"?Resize@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAXI@Z",
            f"?ResizeBuffer@?$DynArray@{cls_key_and_decorated}@@@red@@IEAAXI@Z",

            f"?OnPreSave@{decorated}@@UEAAXAEBUPreSaveContext@@@Z",
            f"?OnPostLoad@{decorated}@@UEAAXAEBUPostLoadContext@@@Z",
            f"?OnPropertyPreChange@{decorated}@@UEAA_NAEBVAccessPath@rtti@@AEAV?$SharedStorage@$$CBVValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@@Z",
            f"?OnPropertyPostChange@{decorated}@@UEAAXAEBVAccessPath@rtti@@AEBV?$SharedStorage@VValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@1@Z",
            f"?OnSerialize@{decorated}@@EEAAXAEAVIFile@@@Z",
            f"?OnPropertyMissing@{decorated}@@UEAA_NVCName@@AEBVVariant@rtti@@@Z",
            f"?OnPropertyTypeMismatch@{decorated}@@UEAA_NVCName@@PEBVProperty@rtti@@AEBVVariant@{len(quals) + 3}@@Z",
            f"?GetPath@{decorated}@@UEBA?AVResourcePath@res@@XZ",
            f"?GetSchemaHash@{decorated}@@UEBAIXZ",
            f"??$HandleFromThis@{cls_key_and_decorated}@@@ISerializable@@QEBA?AV?$THandle@{cls_key_and_decorated}@@@@XZ",
            f"??$WeakHandleFromThis@{cls_key_and_decorated}@@@ISerializable@@QEBA?AV?$WeakHandle@{cls_key_and_decorated}@@@@XZ",
            f"??$HandleFromPtr@{cls_key_and_decorated}@@@@YA?AV?$THandle@{cls_key_and_decorated}@@@@PEB{cls_key_and_decorated}@@@Z"
        ):
            if resolving.findMangledThenLabel(mangled, 1):
                unwind_mangled = f"$unwind${mangled}" # Function unwind info
                if addr := resolving.findMangled(unwind_mangled, 2):
                    createLabel(addr, unwind_mangled, False, SourceType.ANALYSIS)
                    num_derived += 1
        
        resolving.findMangledThenLabel(f"??_7{decorated}@@6B@", 2)
        
        for mangled in (
            f"?sm_classDesc@{decorated}@@0PEBVClassType@rtti@@EB",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YA_KXZ@4IA",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@V?$THandle@{cls_key_and_decorated}@@@@@red@@@@YA_KXZ@4IA",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$THandle@{cls_key_and_decorated}@@@@@@YA_KXZ@4IA",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YA_KXZ@4IA",
            f"?rttiType@?1???$GetTypeObject@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
            f"?rttiType@?1???$GetTypeObject@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
            f"?rttiType@?1???$GetTypeObject@V?$THandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
            f"?rttiType@?1???$GetTypeObject@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
            f"?theName@?1??GetTypeName@?$TTypeName@{cls_key_and_decorated}@@@@SA?BVCName@@XZ@4V3@A",
        ):
            resolving.findMangledThenLabel(mangled, 3)

    for fundamental in ('C', 'D', 'E', 'F', 'G', 'H', 'I', 'M', 'N', '_J', '_K', '_N'):
        quitIfCancelled()
        for mangled in (
            f"??$ResolveRttiType@{fundamental}@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@{fundamental}@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$GetNativeTypeHash@{fundamental}@@YA_KXZ",
            f"??1?$DynArray@{fundamental}@red@@QEAA@XZ",
            f"??4?$DynArray@{fundamental}@red@@QEAAAEAV01@AEBV01@@Z",
            f"?Clear@?$DynArray@{fundamental}@red@@QEAAXXZ",
            f"?Empty@?$DynArray@{fundamental}@red@@QEBA_NXZ",
            f"?PushBack@?$DynArray@{fundamental}@red@@QEAAXAEB{fundamental}@Z",
            f"?PushBack@?$DynArray@{fundamental}@red@@QEAAX$$QEA{fundamental}@Z",
            f"?Reserve@?$DynArray@{fundamental}@red@@QEAAXI@Z",
            f"?Resize@?$DynArray@{fundamental}@red@@QEAAXI@Z",
            f"?ResizeBuffer@?$DynArray@{fundamental}@red@@IEAAXI@Z"
        ):
            resolving.findMangledThenLabel(mangled, 1)

        for mangled in (
            f"?nativeTypeHash@?1???$GetNativeTypeHash@{fundamental}@@YA_KXZ@4IA",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@{fundamental}@red@@@@YA_KXZ@4IA",
            f"?theName@?1??GetTypeName@?$TTypeName@{fundamental}@@SA?BVCName@@XZ@4V3@A"
        ):
            resolving.findMangledThenLabel(mangled, 3)
    
    CROSS_WORKER_SOURCE = '''
import zlib

found_classes = ()
adler32_hashes = frozenset()


def configure(classes, hashes):
    global found_classes, adler32_hashes
    found_classes, adler32_hashes = classes, hashes


def findCrossPairs(entry):
    out_cls_key, out_decorated, out_quals, out_cls_key_and_decorated = entry
    arg_refs = (b"",) + out_quals
    connector_refs = (b"rtti", b"CName", b"ClassType") + out_quals
    out_back_refs = out_cls_key + b"0123456789"[:len(out_quals)]

    object_variants = tuple((prefix, zlib.adler32(prefix)) for prefix in (
        b"??0" + out_decorated + b"@@QEAA@AEB",
        b"??0" + out_decorated + b"@@QEAA@$$QEA",
        b"??4" + out_decorated + b"@@QEAAAEA" + out_back_refs + b"@AEB",
        b"??4" + out_decorated + b"@@QEAAAEA" + out_back_refs + b"@$$QEA",
        b"??8" + out_decorated + b"@@QEBA_NAEB",
        b"??9" + out_decorated + b"@@QEBA_NAEB",
        b"??Y" + out_decorated + b"@@QEAAAEA" + out_back_refs + b"@AEB",
    ))
    cast_prefix = b"??$Cast@" + out_cls_key_and_decorated + b"@@"
    cast_prehash = zlib.adler32(cast_prefix)
    cast_middle = b"@@@YAPEA" + out_cls_key_and_decorated + b"@@PEA"
    handle_cast_middle = b"@@@YA?AV?$THandle@" + out_cls_key_and_decorated + b"@@@@AEBV?$THandle@"

    connector_prefix = b"??$RegisterEventConnector@" + out_cls_key_and_decorated + b"@@"
    connector_prehash = zlib.adler32(connector_prefix)
    connector_middles = tuple(
        b"@@rtti@@YAXVCName@@PEAVClassType@0@P8" + out_decorated + b"@@" + qualifier + b"XAEB"
        for qualifier in (b"EAA", b"EBA"))

    vftable_prefix = b"??_7" + out_decorated + b"@@6B"
    vftable_prehash = zlib.adler32(vftable_prefix)

    hits = []
    for in_cls_key, in_decorated, in_quals, in_cls_key_and_decorated in found_classes:
        if in_decorated == out_decorated:
            continue

        if any(qual in out_quals for qual in in_quals):
            arg_quals = b"".join(
                b"%d" % arg_refs.index(qual) if qual in arg_refs else qual + b"@"
                for qual in in_quals)
            param_quals = b"".join(
                b"%d" % out_quals.index(qual) if qual in out_quals else qual + b"@"
                for qual in in_quals)
        else:
            arg_quals = param_quals = in_decorated + b"@"

        if any(qual in connector_refs for qual in in_quals):
            connector_quals = b"".join(
                b"%d" % connector_refs.index(qual) if qual in connector_refs else qual + b"@"
                for qual in in_quals)
        else:
            connector_quals = param_quals

        param_tail = in_cls_key + param_quals + b"@@Z"
        cast_body = in_cls_key + arg_quals + cast_middle
        handle_cast_body = in_cls_key + arg_quals + handle_cast_middle
        handle_cast_tail = in_cls_key_and_decorated + b"@@@@@Z"
        connector_tail = in_cls_key + connector_quals + b"@@Z@Z"
        vftable_tail = param_quals + b"@@"

        for prefix, prehash in object_variants:
            if zlib.adler32(param_tail, prehash) in adler32_hashes:
                hits.append((prefix + param_tail, 1))
        if zlib.adler32(param_tail, zlib.adler32(cast_body, cast_prehash)) in adler32_hashes:
            hits.append((cast_prefix + cast_body + param_tail, 1))
        if zlib.adler32(handle_cast_tail, zlib.adler32(handle_cast_body, cast_prehash)) in adler32_hashes:
            hits.append((cast_prefix + handle_cast_body + handle_cast_tail, 1))
        for connector_middle in connector_middles:
            connector_body = in_cls_key + arg_quals + connector_middle
            if zlib.adler32(connector_tail, zlib.adler32(connector_body, connector_prehash)) in adler32_hashes:
                hits.append((connector_prefix + connector_body + connector_tail, 1))
        if zlib.adler32(vftable_tail, vftable_prehash) in adler32_hashes:
            hits.append((vftable_prefix + vftable_tail, 2))
    return hits
'''
    
    worker_dir = tempfile.mkdtemp(prefix='ghidra_cross_')
    with open(os.path.join(worker_dir, 'crossworker.py'), 'w') as handle:
        handle.write(CROSS_WORKER_SOURCE)
    sys.path.insert(0, worker_dir)
    sys.modules.pop('crossworker', None)
    import crossworker

    interpreter = sys.executable
    if not os.path.basename(interpreter).lower().startswith('python'):
        interpreter = os.path.join(sys.base_prefix, 'python.exe' if os.name == 'nt' else 'bin/python3')
    multiprocessing.set_executable(interpreter)
    println(f"Spawning {os.cpu_count()} cross-product workers using {interpreter}")

    found_classes = tuple(found_classes)
    with ProcessPoolExecutor(
        max_workers=os.cpu_count(),
        mp_context=multiprocessing.get_context('spawn'),
        initializer=crossworker.configure,
        initargs=(found_classes, frozenset(resolving.adler32_hashes)),
    ) as executor:
        for hits in executor.map(crossworker.findCrossPairs, found_classes, chunksize=32):
            if monitor.isCancelled():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            for candidate, block_idx in hits:
                mangled = candidate.decode('utf-8')
                if resolving.findMangledThenLabel(mangled, block_idx) and block_idx == 1:
                    unwind_mangled = f"$unwind${mangled}"
                    if addr := resolving.findMangled(unwind_mangled, 2):
                        createLabel(addr, unwind_mangled, False, SourceType.ANALYSIS)
                        num_derived += 1
    quitIfCancelled()

    current_program.setEventsEnabled(True)
 
    for err in errors:
        printerr(err)

    println(f"Found {len(found_classes)} RTTI declared classes")
    println(f"Derived {num_derived} symbols")

    should_commit = True

except SystemExit:
    pass
except Exception:
    raise
finally:
    end(should_commit)  # end transaction