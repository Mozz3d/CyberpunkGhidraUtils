# Derive and analyze Cyberpunk RTTI class symbols
#@author Mozz
#@category Cyberpunk
#@keybinding 
#@menupath 
#@toolbar 

import hashlib
import zlib
import re

from collections import defaultdict
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
num_found = 0
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
                decorated = '@'.join(reversed(potential_quals))
                for mangled, cls_key in (
                    (f"?nativeTypeHash@?1???$GetNativeTypeHash@V{decorated}@@@@YA_KXZ@4IA", 'V'),
                    (f"?nativeTypeHash@?1???$GetNativeTypeHash@U{decorated}@@@@YA_KXZ@4IA", 'U'),
                ):
                    if addr := resolving.findMangled(mangled, 3):
                        if len(potential_quals) > 1 and (qual := potential_quals[0]) and len(qual) > 2:
                            resolving.seen_namespaces.add(qual)
                        yield cls_key, decorated, addr, mangled
                        break
                else:
                    continue
                break

    @staticmethod
    def resolveUniqueTypes():
        for name in (
            "CName",
            "DataBuffer",
            "DeferredDataBuffer@serialization",
            "EulerAngles",
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
                    yield cls_key, name, native_type_hash_addr, mangled
                    break

    #enumType_ctor_name = '??0EnumType@rtti@@QEAA@VCName@@I_N@Z'
    #enumType_ctor_addr = findMangled(enumType_ctor_name)
    #"?nativeTypeHash@?1???$GetNativeTypeHash@W4{}@@@@YA_KXZ@4IA"

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
    for cls_key, decorated, native_type_hash_addr, native_type_hash_mangled in chain(
        resolving.resolveClassTypes(),
        resolving.resolveUniqueTypes(),
    ):
        quitIfCancelled()
        demangling.label(native_type_hash_addr, native_type_hash_mangled)
        num_found += 1

        copy_spec = ''
        cls_key_and_decorated = f"{cls_key}{decorated}"
        cls_key_and_back_refs = f"{cls_key}{''.join(str(i) for i in range(decorated.count('@') + 1))}"
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
            f"??4{decorated}@@QEAAAEA{cls_key_and_back_refs}@$$QEA{cls_key_and_back_refs}@@Z",
            f"??4?$THandle@{cls_key_and_decorated}@@@@QEAAAEAV?$THandle@{cls_key_and_decorated}@@@@AEBV?$THandle@{cls_key_and_decorated}@@@@@Z",
            f"??8{decorated}@@QEBA_NAEB{cls_key_and_back_refs}@@Z",
            f"??9{decorated}@@QEBA_NAEB{cls_key_and_back_refs}@@Z",
            f"??Y{decorated}@@QEAAAEA{cls_key_and_back_refs}@AEB{cls_key_and_back_refs}@@Z",
            f"??_G{decorated}@@UEAAPEAXI@Z",
            
            f"??1?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@UEAA@XZ",
            f"??_G?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@UEAAPEAXI@Z",
            f"?OnConstruct@?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@EEBAXPEAX@Z",
            f"?OnDestruct@?$TNativeClass{copy_spec}@{cls_key_and_decorated}@@@rtti@@EEBAXPEAX@Z",

            f"??$GetNativeTypeHash@{cls_key_and_decorated}@@@@YA_KXZ",
            f"??$GetNativeTypeHash@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YA_KXZ",
            f"??$GetNativeTypeHash@V?$THandle@{cls_key_and_decorated}@@@@@@YA_KXZ",
            f"??$GetNativeTypeHash@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YA_KXZ",
            f"?GetNativeClass@{decorated}@@UEBAPEBVClassType@rtti@@XZ",
            f"?GetClass@{decorated}@@UEBAPEBVClassType@rtti@@XZ",
            f"?GetFriendlyName@{decorated}@@UEBA?AVString@red@@XZ",
            f"?GetFriendlyDescription@{decorated}@@UEBAPEBDXZ",
            f"?GetDescription@{decorated}@@UEBA?AVString@red@@XZ",
            f"?RegisterProperties@{decorated}@@SAXPEAVClassType@rtti@@@Z",

            f"??$ResolveRttiType@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$THandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$TResRef@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$TResAsyncRef@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$THandle@{cls_key_and_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$WeakHandle@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$TResRef@{cls_key_and_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@V?$TResAsyncRef@{cls_key_and_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",

            f"??$CreateObject@{cls_key_and_decorated}@@@ClassType@rtti@@QEBAPEA{cls_key_and_decorated}@@XZ",
            f"??$GetTypeObject@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ",
            f"??$GetTypeObject@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$GetTypeObject@V?$THandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ"
            f"??$GetTypeObject@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
            f"?GetMemoryPool@{decorated}@@UEBAAEBVPool@memory@red@@XZ",

            f"??_G?$DataUpdater@{cls_key_and_decorated}@@@TweakDB@data@game@@UEAAPEAXI@Z",

            f"??$IsA@{cls_key_and_decorated}@@@ClassType@rtti@@QEBA_NXZ",

            f"?Clear@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAXXZ",
            f"?Empty@?$DynArray@{cls_key_and_decorated}@@@red@@QEBA_NXZ",
            f"?Reserve@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAXI@Z",
            f"?Resize@?$DynArray@{cls_key_and_decorated}@@@red@@QEAAXI@Z",
            f"?ResizeBuffer@?$DynArray@{cls_key_and_decorated}@@@red@@IEAAXI@Z",

            f"?OnPreSave@{decorated}@@UEAAXAEBUPreSaveContext@@@Z",
            f"?OnPostLoad@{decorated}@@UEAAXAEBUPostLoadContext@@@Z",
            f"?OnPropertyPreChange@{decorated}@@UEAA_NAEBVAccessPath@rtti@@AEAV?$SharedStorage@$$CBVValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@@Z",
            f"?OnPropertyPostChange@{decorated}@@UEAAXAEBVAccessPath@rtti@@AEBV?$SharedStorage@VValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@1@Z",
            f"?OnSerialize@{decorated}@@EEAAXAEAVIFile@@@Z",
            f"?OnPropertyMissing@{decorated}@@UEAA_NVCName@@AEBVVariant@rtti@@@Z",
            f"?OnPropertyTypeMismatch@{decorated}@@UEAA_NVCName@@PEBVProperty@rtti@@AEBVVariant@4@@Z",
            f"?GetPath@{decorated}@@UEBA?AVResourcePath@res@@XZ",
            f"?GetSchemaHash@{decorated}@@UEBAIXZ"
        ):
            resolving.findMangledThenLabel(mangled, 1)

        resolving.findMangledThenLabel(f"??_7{decorated}@@6B@", 2)

        for mangled in (
            f"?$TSS0@?1???$GetTypeObject@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ@4HA",
            f"?$TSS0@?1???$GetNativeTypeHash@{cls_key_and_decorated}@@@@YA_KXZ@4HA",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$THandle@{cls_key_and_decorated}@@@@@@YA_KXZ@4IA",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YA_KXZ@4IA",
            f"?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@V?$THandle@{cls_key_and_decorated}@@@@@red@@@@YA_KXZ@4IA",
            f"?sm_classDesc@{decorated}@@0PEBVClassType@rtti@@EB",
            f"?theName@?1??GetTypeName@?$TTypeName@{cls_key_and_decorated}@@@@SA?BVCName@@XZ@4V3@A",
            f"?rttiType@?1???$GetTypeObject@{cls_key_and_decorated}@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
            f"?rttiType@?1???$GetTypeObject@V?$DynArray@{cls_key_and_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
            f"?rttiType@?1???$GetTypeObject@V?$THandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
            f"?rttiType@?1???$GetTypeObject@V?$WeakHandle@{cls_key_and_decorated}@@@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
        ):
            resolving.findMangledThenLabel(mangled, 3)

    for fundamental in ('C', 'D', 'E', 'F', 'G', 'H', 'I', 'M', 'N', '_J', '_K', '_N'):
        quitIfCancelled()
        for mangled in (
            f"??$ResolveRttiType@{fundamental}@@YAPEBVIType@rtti@@XZ",
            f"??$ResolveRttiType@V?$DynArray@{fundamental}@red@@@@YAPEBVIType@rtti@@XZ",
            f"??$GetNativeTypeHash@{fundamental}@@YA_KXZ",
            f"??1?$DynArray@{fundamental}@@@red@@QEAA@XZ",
            f"?Clear@?$DynArray@{fundamental}@@@red@@QEAAXXZ",
            f"?Empty@?$DynArray@{fundamental}@@@red@@QEBA_NXZ",
            f"?Reserve@?$DynArray@{fundamental}@@@red@@QEAAXI@Z",
            f"?Resize@?$DynArray@{fundamental}@@@red@@QEAAXI@Z",
            f"?ResizeBuffer@?$DynArray@{fundamental}@@@red@@IEAAXI@Z",
        ):
            resolving.findMangledThenLabel(mangled, 1)

        for mangled in (
            f"?nativeTypeHash@?1???$GetNativeTypeHash@{fundamental}@@YA_KXZ@4IA",
            f"?$TSS0@?1???$GetNativeTypeHash@{fundamental}@@@@YA_KXZ@4HA",
        ):
            resolving.findMangledThenLabel(mangled, 3)

    class_type_reg_event_connector_name = (
        '?Internal_RegisterEventConnector@ClassType@rtti@@QEAAXVCName@@PEBV12@AEBV'
        '?$FixedSizeFunction@$$A6AXAEAVISerializable@@AEBV?$THandle@VEvent@red@@@@@Z$0BA@$07@red@@@Z'
    )
    class_type_reg_event_connector_addr = resolving.findMangledThenLabel(class_type_reg_event_connector_name, 1)
    println(f"Located `rtti::ClassType::Internal_RegisterEventConnector` at {class_type_reg_event_connector_addr}")

    for reg_event_conncector_func in getFunctionAt(class_type_reg_event_connector_addr).getCallingFunctions(monitor):
        quitIfCancelled()
        event_quald_name = None

        for instruction in listing.getInstructions(reg_event_conncector_func.getBody(), True):
            ref = instruction.getPrimaryReference(1)

            if ref is None:
                continue

            data = getDataAt(ref.getToAddress())
            if data is None:
                continue

            data_symbol = data.getPrimarySymbol()

            if 'sm_classDesc' in data_symbol.getName():
                event_quald_name = str(data_symbol.getParentNamespace())

        if event_quald_name is None:
            errors.append("Could not find event class descriptor")
            continue

        for reg_prop_func in reg_event_conncector_func.getCallingFunctions(monitor):
            type_quald_name = str(reg_prop_func.getParentNamespace())
            
            type_quals  = list(reversed(type_quald_name.split(Namespace.DELIMITER)))
            event_quals = list(reversed(event_quald_name.split(Namespace.DELIMITER)))

            templated_event_quals = (
                str(type_quals.index(qual) + 1) if qual in type_quals else qual
                for qual in event_quals
            )
            param_event_quals = (
                str(type_quals.index(qual) + 3) if qual in type_quals else qual
                for qual in event_quals
            )
            
            deco_event_quals          = '@'.join(event_quals)
            deco_type_quals           = '@'.join(type_quals)
            deco_template_event_quals = '@'.join(templated_event_quals)
            deco_param_event_quals    = '@'.join(param_event_quals)

            for mangled in (
                f'??$RegisterEventConnector@V{deco_type_quals}@@V{deco_template_event_quals}@@rtti@@YAXVCName@@PEAVClassType@0@P8{deco_type_quals}@@EAAXAEBV{deco_param_event_quals}@@Z@Z',
                f'??$RegisterEventConnector@V{deco_type_quals}@@U{deco_template_event_quals}@@rtti@@YAXVCName@@PEAVClassType@0@P8{deco_type_quals}@@EAAXAEBU{deco_param_event_quals}@@Z@Z',
                f'??$RegisterEventConnector@U{deco_type_quals}@@V{deco_template_event_quals}@@rtti@@YAXVCName@@PEAVClassType@0@P8{deco_type_quals}@@EAAXAEBV{deco_param_event_quals}@@Z@Z',
                f'??$RegisterEventConnector@U{deco_type_quals}@@U{deco_template_event_quals}@@rtti@@YAXVCName@@PEAVClassType@0@P8{deco_type_quals}@@EAAXAEBU{deco_param_event_quals}@@Z@Z',
                f"?GetEventName@{deco_event_quals}@@UEBA?AVCName@@XZ",
            ):
                resolving.findMangledThenLabel(mangled, 1)
    
    current_program.setEventsEnabled(True)
 
    for err in errors:
        printerr(err)

    println(f"Found {num_found} RTTI declared classes")
    println(f"Derived {num_derived} symbols")

    should_commit = True

except SystemExit:
    pass
except Exception:
    raise
finally:
    end(should_commit)  # end transaction
