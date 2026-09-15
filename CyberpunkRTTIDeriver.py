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

from concurrent.futures import ProcessPoolExecutor
from itertools import combinations, chain

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType, RefType

from ghidra.app.util.demangler.microsoft import MicrosoftDemangler

current_program = currentProgram
listing = current_program.getListing()
errors = []
found_classes = []
num_derived = 0

FUNDAMENTALS = (
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', '_J', '_K', '_N', '_W',
)

SLOT_NAMES = (
    'decorated',
    'cls_decorated',
    'cls_back_refs',
    'copy_spec',
    'variant_index',
    'fundamental',
)

TEMPLATE_FIELD_RE = re.compile(r'\{(\w+)\}')

def compileTemplates(templates, names):
    compiled = []
    for template in templates:
        parts = TEMPLATE_FIELD_RE.split(template)
        head = parts[0].encode('utf-8')
        compiled.append((
            head,
            zlib.adler32(head),
            tuple(
                (names.index(parts[index]), parts[index + 1].encode('utf-8'))
                for index in range(1, len(parts), 2)
            ),
        ))
    return tuple(compiled)


def packSlots(names, **values):
    return tuple(values.get(name, '').encode('utf-8') for name in names)


def rollSteps(state, steps, slots):
    for slot, static in steps:
        state = zlib.adler32(static, zlib.adler32(slots[slot], state))
    return state


def joinSteps(head, steps, slots):
    parts = [head]
    for slot, static in steps:
        parts.append(slots[slot])
        parts.append(static)
    return b''.join(parts)


CLASS_FUNCTIONS = compileTemplates((
    "??0{decorated}@@QEAA@XZ",
    "??0{decorated}@@AEAA@XZ",
    "??0{decorated}@@IEAA@XZ",
    "??0{decorated}@@QEAA@AEB{cls_back_refs}@@Z",
    "??0{decorated}@@QEAA@$$QEA{cls_back_refs}@@Z",

    "??0{decorated}@@QEAA@V?$THandle@{cls_decorated}@@@@@Z",
    "??0{decorated}@@QEAA@AEBV?$THandle@{cls_decorated}@@@@@Z",
    "??0?$THandle@{cls_decorated}@@@@QEAA@XZ",
    "??0?$WeakHandle@{cls_decorated}@@@@QEAA@XZ",
    "??1{decorated}@@UEAA@XZ",
    "??1{decorated}@@QEAA@XZ",
    "??1?$DynArray@{cls_decorated}@@@red@@QEAA@XZ",
    "??1?$SharedStorage@{cls_decorated}@@VAtomicSharedStorage@internal@red@@X@red@@QEAA@XZ",
    "??1?$THandle@{cls_decorated}@@@@QEAA@XZ",
    "??1?$WeakHandle@{cls_decorated}@@@@QEAA@XZ",
    "??4{decorated}@@QEAAAEA{cls_back_refs}@AEB{cls_back_refs}@@Z",
    "??4{decorated}@@QEAAAEA{cls_back_refs}@$$QEA{cls_back_refs}@@Z",
    "??4?$DynArray@{cls_decorated}@@@red@@QEAAAEAV01@AEBV01@@Z",
    "??4?$DynArray@{cls_decorated}@@@red@@QEAAAEAV01@$$QEAV01@@Z",
    "??4?$SharedStorage@{cls_decorated}@@VAtomicSharedStorage@internal@red@@X@red@@QEAAAEAV01@AEBV01@@Z",
    "??4?$THandle@{cls_decorated}@@@@QEAAAEAV0@AEBV0@@Z",
    "??4?$THandle@{cls_decorated}@@@@QEAAAEAV0@$$QEAV0@@Z",
    "??8{decorated}@@QEBA_NAEB{cls_back_refs}@@Z",
    "??9{decorated}@@QEBA_NAEB{cls_back_refs}@@Z",
    "??Y{decorated}@@QEAAAEA{cls_back_refs}@AEB{cls_back_refs}@@Z",
    "??_G{decorated}@@UEAAPEAXI@Z",

    "??_G?$TNativeClass{copy_spec}@{cls_decorated}@@@rtti@@UEAAPEAXI@Z",
    "?Copy@?$TNativeClass{copy_spec}@{cls_decorated}@@@rtti@@EEBAXPEAXPEBX@Z",
    "?OnConstruct@?$TNativeClass{copy_spec}@{cls_decorated}@@@rtti@@EEBAXPEAX@Z",
    "?OnDestruct@?$TNativeClass{copy_spec}@{cls_decorated}@@@rtti@@EEBAXPEAX@Z",

    "??$IsA@{cls_decorated}@@@ClassType@rtti@@QEBA_NXZ",
    "??$CreateObject@{cls_decorated}@@@ClassType@rtti@@QEBAPEA{cls_decorated}@@XZ",
    "??$CreateHandle@{cls_decorated}@@$$V@@YA?AV?$THandle@{cls_decorated}@@@@XZ",
    "??$CreateUniquePtr@{cls_decorated}@@$$V@red@@YA?AV?$UniquePtr@{cls_decorated}@@VDefaultUniquePtrDestructor@memory@red@@@0@XZ",
    "??$CreateSharedPtr@{cls_decorated}@@$$V@red@@YA?AV?$SharedStorage@{cls_decorated}@@VAtomicSharedStorage@internal@red@@X@0@XZ",

    "??$GetTypeObject@{cls_decorated}@@@@YAPEBVIType@rtti@@XZ",
    "??$GetTypeObject@V?$DynArray@{cls_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ",
    "??$GetTypeObject@V?$THandle@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
    "??$GetTypeObject@V?$WeakHandle@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ",

    "?GetNativeClass@{decorated}@@UEBAPEBVClassType@rtti@@XZ",
    "?GetClass@{decorated}@@UEBAPEBVClassType@rtti@@XZ",
    "?GetFriendlyName@{decorated}@@UEBA?AVString@red@@XZ",
    "?GetFriendlyDescription@{decorated}@@UEBAPEBDXZ",
    "?GetDescription@{decorated}@@UEBA?AVString@red@@XZ",
    "?RegisterProperties@{decorated}@@SAXPEAVClassType@rtti@@@Z",

    "??$GetNativeTypeHash@{cls_decorated}@@@@YA_KXZ",
    "??$GetNativeTypeHash@V?$DynArray@{cls_decorated}@@@red@@@@YA_KXZ",
    "??$GetNativeTypeHash@V?$DynArray@V?$THandle@{cls_decorated}@@@@@red@@@@YA_KXZ",
    "??$GetNativeTypeHash@V?$THandle@{cls_decorated}@@@@@@YA_KXZ",
    "??$GetNativeTypeHash@V?$WeakHandle@{cls_decorated}@@@@@@YA_KXZ",

    "??$ResolveRttiType@{cls_decorated}@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$THandle@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$WeakHandle@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$TResRef@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$TResAsyncRef@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$DynArray@{cls_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$DynArray@V?$THandle@{cls_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$DynArray@V?$WeakHandle@{cls_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$DynArray@V?$TResRef@{cls_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$DynArray@V?$TResAsyncRef@{cls_decorated}@@@@@red@@@@YAPEBVIType@rtti@@XZ",

    "?GetMemoryPool@{decorated}@@UEBAAEBVPool@memory@red@@XZ",

    "??_G?$DataUpdater@{cls_decorated}@@@TweakDB@data@game@@UEAAPEAXI@Z",

    "?Clear@?$DynArray@{cls_decorated}@@@red@@QEAAXXZ",
    "?Empty@?$DynArray@{cls_decorated}@@@red@@QEBA_NXZ",
    "?PushBack@?$DynArray@{cls_decorated}@@@red@@QEAAXAEB{cls_decorated}@@@Z",
    "?PushBack@?$DynArray@{cls_decorated}@@@red@@QEAAX$$QEA{cls_decorated}@@@Z",
    "?Reserve@?$DynArray@{cls_decorated}@@@red@@QEAAXI@Z",
    "?Resize@?$DynArray@{cls_decorated}@@@red@@QEAAXI@Z",
    "?ResizeBuffer@?$DynArray@{cls_decorated}@@@red@@IEAAXI@Z",

    "?OnPreSave@{decorated}@@UEAAXAEBUPreSaveContext@@@Z",
    "?OnPostLoad@{decorated}@@UEAAXAEBUPostLoadContext@@@Z",
    "?OnPropertyPreChange@{decorated}@@UEAA_NAEBVAccessPath@rtti@@AEAV?$SharedStorage@$$CBVValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@@Z",
    "?OnPropertyPostChange@{decorated}@@UEAAXAEBVAccessPath@rtti@@AEBV?$SharedStorage@VValueHolder@rtti@@VAtomicSharedStorage@internal@red@@X@red@@1@Z",
    "?OnSerialize@{decorated}@@EEAAXAEAVIFile@@@Z",
    "?OnPropertyMissing@{decorated}@@UEAA_NVCName@@AEBVVariant@rtti@@@Z",
    "?OnPropertyTypeMismatch@{decorated}@@UEAA_NVCName@@PEBVProperty@rtti@@AEBVVariant@{variant_index}@@Z",
    "?GetPath@{decorated}@@UEBA?AVResourcePath@res@@XZ",
    "?GetSchemaHash@{decorated}@@UEBAIXZ",

    "??$HandleFromThis@{cls_decorated}@@@ISerializable@@QEBA?AV?$THandle@{cls_decorated}@@@@XZ",
    "??$WeakHandleFromThis@{cls_decorated}@@@ISerializable@@QEBA?AV?$WeakHandle@{cls_decorated}@@@@XZ",
    "??$HandleFromPtr@{cls_decorated}@@@@YA?AV?$THandle@{cls_decorated}@@@@PEB{cls_decorated}@@@Z",
), SLOT_NAMES)

CLASS_DATA = compileTemplates((
    "?sm_classDesc@{decorated}@@0PEBVClassType@rtti@@EB",
    "?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@{cls_decorated}@@@red@@@@YA_KXZ@4IA",
    "?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@V?$THandle@{cls_decorated}@@@@@red@@@@YA_KXZ@4IA",
    "?nativeTypeHash@?1???$GetNativeTypeHash@V?$THandle@{cls_decorated}@@@@@@YA_KXZ@4IA",
    "?nativeTypeHash@?1???$GetNativeTypeHash@V?$WeakHandle@{cls_decorated}@@@@@@YA_KXZ@4IA",
    "?rttiType@?1???$GetTypeObject@{cls_decorated}@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
    "?rttiType@?1???$GetTypeObject@V?$DynArray@{cls_decorated}@@@red@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
    "?rttiType@?1???$GetTypeObject@V?$THandle@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
    "?rttiType@?1???$GetTypeObject@V?$WeakHandle@{cls_decorated}@@@@@@YAPEBVIType@rtti@@XZ@4PEBV12@EB",
    "?theName@?1??GetTypeName@?$TTypeName@{cls_decorated}@@@@SA?BVCName@@XZ@4V3@A",
), SLOT_NAMES)

FUNDAMENTAL_FUNCTIONS = compileTemplates((
    "??$ResolveRttiType@{fundamental}@@YAPEBVIType@rtti@@XZ",
    "??$ResolveRttiType@V?$DynArray@{fundamental}@red@@@@YAPEBVIType@rtti@@XZ",
    "??$GetNativeTypeHash@{fundamental}@@YA_KXZ",
    "??1?$DynArray@{fundamental}@red@@QEAA@XZ",
    "??4?$DynArray@{fundamental}@red@@QEAAAEAV01@AEBV01@@Z",
    "?Empty@?$DynArray@{fundamental}@red@@QEBA_NXZ",
    "?PushBack@?$DynArray@{fundamental}@red@@QEAAXAEB{fundamental}@Z",
    "?PushBack@?$DynArray@{fundamental}@red@@QEAAX$$QEA{fundamental}@Z",
    "?Reserve@?$DynArray@{fundamental}@red@@QEAAXI@Z",
    "?Resize@?$DynArray@{fundamental}@red@@QEAAXI@Z",
), SLOT_NAMES)

FUNDAMENTAL_DATA = compileTemplates((
    "?nativeTypeHash@?1???$GetNativeTypeHash@{fundamental}@@YA_KXZ@4IA",
    "?nativeTypeHash@?1???$GetNativeTypeHash@V?$DynArray@{fundamental}@red@@@@YA_KXZ@4IA",
    "?theName@?1??GetTypeName@?$TTypeName@{fundamental}@@SA?BVCName@@XZ@4V3@A",
), SLOT_NAMES)

NATIVE_TYPE_HASH_HEAD = b"?nativeTypeHash@?1???$GetNativeTypeHash@"
NATIVE_TYPE_HASH_TAIL = b"@@@@YA_KXZ@4IA"
NATIVE_TYPE_HASH_KEYS = tuple(
    (cls_key, zlib.adler32(NATIVE_TYPE_HASH_HEAD + cls_key), cls_key.decode('utf-8'))
    for cls_key in (b'V', b'U')
)


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
            num_derived += 1
            println(f"Derived `{str(demangled).strip()}` at {addr}")
        except Exception as e:
            errors.append(f"Could not apply label '{str(demangled).strip()}' at {addr}: {e}")


class resolving:
    seen_namespaces = set()

    _ADLER32_RE = re.compile(r'Adler32: (\b\d+\b)')
    _SHA256_RE = re.compile(r'SHA256: ([a-f0-9]{64})')

    adler32_hashes = set()
    block_sha256_maps = []

    @staticmethod
    def getHashesAt(addr):
        comment = getPlateComment(addr)
        if not comment:
            return (), ()
        a32s = (int(m) for m in resolving._ADLER32_RE.findall(comment))
        sha256s = (int(m, 16) for m in resolving._SHA256_RE.findall(comment))
        return a32s, sha256s

    @staticmethod
    def templateHits(templates, slots):
        hashes = resolving.adler32_hashes
        for head, head_state, steps in templates:
            if rollSteps(head_state, steps, slots) in hashes:
                yield joinSteps(head, steps, slots)

    @staticmethod
    def findEncoded(encoded, block_idx):
        return resolving.block_sha256_maps[block_idx].get(
            int.from_bytes(hashlib.sha256(encoded).digest(), 'big')
        )

    @staticmethod
    def findEncodedThenLabel(encoded, block_idx):
        if addr := resolving.findEncoded(encoded, block_idx):
            demangling.label(addr, encoded.decode('utf-8'))
            return addr

    @staticmethod
    def findMangled(mangled, block_idx=1):
        encoded = mangled.encode('utf-8')
        if zlib.adler32(encoded) in resolving.adler32_hashes:
            return resolving.findEncoded(encoded, block_idx)

    @staticmethod
    def findMangledThenLabel(mangled, block_idx):
        if addr := resolving.findMangled(mangled, block_idx):
            demangling.label(addr, mangled)
            return addr

    @staticmethod
    def labelUnwind(encoded):
        global num_derived
        unwind = b"$unwind$" + encoded
        if zlib.adler32(unwind) in resolving.adler32_hashes:
            if addr := resolving.findEncoded(unwind, 2):
                createLabel(addr, unwind.decode('utf-8'), False, SourceType.ANALYSIS)
                num_derived += 1

    @staticmethod
    def findNativeTypeHash(decorated):
        encoded_decorated = decorated.encode('utf-8')
        for cls_key, head_state, cls_key_text in NATIVE_TYPE_HASH_KEYS:
            rolled = zlib.adler32(NATIVE_TYPE_HASH_TAIL, zlib.adler32(encoded_decorated, head_state))
            if rolled not in resolving.adler32_hashes:
                continue
            encoded = NATIVE_TYPE_HASH_HEAD + cls_key + encoded_decorated + NATIVE_TYPE_HASH_TAIL
            if addr := resolving.findEncoded(encoded, 3):
                return cls_key_text, addr, encoded.decode('utf-8')

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
        class_type_ctor_mangled = '??0ClassType@rtti@@QEAA@VCName@@II@Z'
        class_type_ctor_addr = resolving.findMangledThenLabel(class_type_ctor_mangled, 1)
        if class_type_ctor_addr is None:
            raise RuntimeError("Could not locate `rtti::ClassType::ClassType`, are hashes imported?")
        println(f"Located `rtti::ClassType::ClassType` at {class_type_ctor_addr}")

        for init_func in getFunctionAt(class_type_ctor_addr).getCallingFunctions(monitor):
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
                if found := resolving.findNativeTypeHash('@'.join(quals)):
                    cls_key, addr, mangled = found
                    if len(potential_quals) > 1 and (qual := potential_quals[0]) and len(qual) > 2:
                        resolving.seen_namespaces.add(qual)
                    yield cls_key, quals, addr, mangled
                    break

    @staticmethod
    def resolveUniqueTypes():
        for name in (
            "Box@math",
            "CDateTime",
            "CName",
            "DataBuffer",
            "DeferredDataBuffer@serialization",
            "EulerAngles@math",
            "QsTransform@math",
            "Quaternion@math",
            "SharedDataBuffer",
            "String@red",
            "TweakDBID@data@game",
            "Vector2@math",
            "Vector3@math",
            "Vector4@math",
        ):
            if found := resolving.findNativeTypeHash(name):
                cls_key, addr, mangled = found
                yield cls_key, tuple(name.split('@')), addr, mangled


CROSS_WORKER_SOURCE = '''
import re
import zlib

found_classes = ()
adler32_hashes = frozenset()

FUNDAMENTALS = ()

TEMPLATE_FIELD_RE = re.compile(r'\\{(\\w+)\\}')

CONTAINER_SLOT = ('container',)
SIGNATURE_SLOTS = ('key_type', 'value_type', 'key_sig', 'value_sig')
CONTAINER_SLOTS = CONTAINER_SLOT + SIGNATURE_SLOTS

CROSS_OUTER_SLOTS = ('out_decorated', 'out_cls_decorated', 'out_cls_back_refs')
CROSS_INNER_SLOTS = ('in_param', 'in_arg', 'in_connector', 'in_cls_decorated', 'in_param_quals')
CROSS_SLOTS = CROSS_OUTER_SLOTS + CROSS_INNER_SLOTS


def compileTemplates(templates, names):
    compiled = []
    for template in templates:
        parts = TEMPLATE_FIELD_RE.split(template)
        head = parts[0].encode('utf-8')
        compiled.append((
            head,
            zlib.adler32(head),
            tuple(
                (names.index(parts[index]), parts[index + 1].encode('utf-8'))
                for index in range(1, len(parts), 2)
            ),
        ))
    return tuple(compiled)


def compileCrossTemplates(templates):
    compiled = []
    for template in templates:
        parts = TEMPLATE_FIELD_RE.split(template)
        steps = tuple(
            (CROSS_SLOTS.index(parts[index]), parts[index + 1].encode('utf-8'))
            for index in range(1, len(parts), 2)
        )
        split = next(
            (index for index, (slot, _) in enumerate(steps) if CROSS_SLOTS[slot] in CROSS_INNER_SLOTS),
            len(steps),
        )
        head = parts[0].encode('utf-8')
        compiled.append((head, zlib.adler32(head), steps[:split], steps[split:]))
    return tuple(compiled)


def packSlots(names, **values):
    return tuple(values.get(name, '').encode('utf-8') for name in names)


def rollSteps(state, steps, slots):
    for slot, static in steps:
        state = zlib.adler32(static, zlib.adler32(slots[slot], state))
    return state


def joinSteps(head, steps, slots):
    parts = [head]
    for slot, static in steps:
        parts.append(slots[slot])
        parts.append(static)
    return b''.join(parts)


CONTAINER_TEMPLATES = compileTemplates((
    "??0{container}QEAA@AEBV01@@Z",
    "??0{container}QEAA@$$QEAV01@@Z",
    "??1{container}QEAA@XZ",
    "??4{container}QEAAAEAV01@AEBV01@@Z",
    "??4{container}QEAAAEAV01@$$QEAV01@@Z",
    "??A{container}QEAAAEA{value_sig}AEB{key_sig}@Z",
    "??A{container}QEBAAEB{value_sig}AEB{key_sig}@Z",
    "?Clear@{container}QEAAXXZ",
    "?GetKeys@{container}QEBA?AV?$DynArray@{key_type}@2@XZ",
    "?GetValues@{container}QEBAXAEAV?$DynArray@{value_type}@2@@Z",
    "?GetValues@{container}QEBA?AV?$DynArray@{value_type}@2@XZ",
    "?Reserve@{container}QEAAXI@Z",
    "?Shrink@{container}QEAAXXZ",
), CONTAINER_SLOTS)

CROSS_FUNCTIONS = compileCrossTemplates((
    "??0{out_decorated}@@QEAA@{in_param}@Z",
    "??0{out_decorated}@@QEAA@AEA{in_param}@Z",
    "??0{out_decorated}@@QEAA@AEB{in_param}@Z",
    "??0{out_decorated}@@QEAA@PEA{in_param}@Z",
    "??0{out_decorated}@@QEAA@PEB{in_param}@Z",
    "??0{out_decorated}@@QEAA@$$QEA{in_param}@Z",
    "??0{out_decorated}@@QEAA@V?$THandle@{in_cls_decorated}@@@@@Z",
    "??0{out_decorated}@@QEAA@AEBV?$THandle@{in_cls_decorated}@@@@@Z",
    "??0{out_decorated}@@QEAA@V?$WeakHandle@{in_cls_decorated}@@@@@Z",
    "??0{out_decorated}@@QEAA@AEBV?$WeakHandle@{in_cls_decorated}@@@@@Z",
    "??$CreateHandle@{out_cls_decorated}@@AEA{in_arg}@@@YA?AV?$THandle@{out_cls_decorated}@@@@AEA{in_param}@Z",
    "??$CreateSharedPtr@{out_cls_decorated}@@AEA{in_arg}@@red@@YA?AV?$SharedStorage@{out_cls_decorated}@@VAtomicSharedStorage@internal@red@@X@1@AEA{in_param}@Z",
    "??$CreateUniquePtr@{out_cls_decorated}@@AEA{in_arg}@@red@@YA?AV?$UniquePtr@{out_cls_decorated}@@VDefaultUniquePtrDestructor@memory@red@@@1@AEA{in_param}@Z",
    "??4{out_decorated}@@QEAAAEA{out_cls_back_refs}@AEB{in_param}@Z",
    "??4?$THandle@{out_cls_decorated}@@@@QEAAAEAV0@AEBV?$THandle@{in_cls_decorated}@@@@@Z",
    "??4?$THandle@{out_cls_decorated}@@@@QEAAAEAV0@$$QEAV?$THandle@{in_cls_decorated}@@@@@Z",
    "??$Cast@{out_cls_decorated}@@{in_arg}@@@YAPEA{out_cls_decorated}@@PEA{in_param}@Z",
    "??$Cast@{out_cls_decorated}@@{in_arg}@@@YA?AV?$THandle@{out_cls_decorated}@@@@AEBV?$THandle@{in_cls_decorated}@@@@@Z",
    "??$RegisterEventConnector@{out_cls_decorated}@@{in_arg}@@rtti@@YAXVCName@@PEAVClassType@0@P8{out_decorated}@@EAAXAEB{in_connector}@@Z@Z",
))

CROSS_VFTABLE = compileCrossTemplates((
    "??_7{out_decorated}@@6B{in_param_quals}@@",
))


def configure(classes, hashes, fundamentals):
    global found_classes, adler32_hashes, FUNDAMENTALS
    found_classes, adler32_hashes, FUNDAMENTALS = classes, hashes, fundamentals


def containerHits(key_type, key_quals, value_type, value_quals):
    arg_refs = ("",) + key_quals
    if any(qual in arg_refs for qual in value_quals):
        value_arg = value_type[0] + "".join(
            str(arg_refs.index(qual)) if qual in arg_refs else f"{qual}@"
            for qual in value_quals) + "@"
    else:
        value_arg = value_type

    policy_refs = arg_refs + tuple(qual for qual in value_quals if qual not in arg_refs)
    red_ref = str(policy_refs.index("red")) if "red" in policy_refs else "red@"

    value_sig = value_type if not value_quals else value_type[0] + "".join(
        "1" if qual == "red" else f"{qual}@" for qual in value_quals) + "@"
    sig_refs = ("", "red") + tuple(qual for qual in value_quals if qual != "red")
    key_sig = key_type if not key_quals else key_type[0] + "".join(
        str(sig_refs.index(qual)) if qual in sig_refs else f"{qual}@"
        for qual in key_quals) + "@"

    adler32, hashes = zlib.adler32, adler32_hashes
    signature_slots = packSlots(
        SIGNATURE_SLOTS,
        key_type=key_type,
        value_type=value_type,
        key_sig=key_sig,
        value_sig=value_sig,
    )

    for container in (
        f"?$HashMap@{key_type}{value_arg}U?$DefaultHashPolicy@{key_type}@{red_ref}@@red@@",
        f"?$Map@{key_type}{value_arg}U?$less@{key_type}@std@@@red@@",
    ):
        slots = (container.encode('utf-8'),) + signature_slots
        for head, head_state, steps in CONTAINER_TEMPLATES:
            checksum = head_state
            for slot, static in steps:
                checksum = adler32(static, adler32(slots[slot], checksum))
            if checksum in hashes:
                yield joinSteps(head, steps, slots).decode('utf-8'), 1


def crossHits(entry):
    out_cls_key, out_decorated, out_quals, out_cls_decorated = entry
    arg_refs = ("",) + out_quals
    connector_refs = ("rtti", "CName", "ClassType") + out_quals
    out_full = out_cls_decorated + "@@"

    outer_slots = packSlots(
        CROSS_OUTER_SLOTS,
        out_decorated=out_decorated,
        out_cls_decorated=out_cls_decorated,
        out_cls_back_refs=out_cls_key + "0123456789"[:len(out_quals)],
    )
    adler32, hashes = zlib.adler32, adler32_hashes
    prepared_slots = outer_slots + packSlots(CROSS_INNER_SLOTS)
    prepared_functions = tuple(
        (joinSteps(head, outer, prepared_slots), rollSteps(head_state, outer, prepared_slots), inner)
        for head, head_state, outer, inner in CROSS_FUNCTIONS
    )
    prepared_vftable = tuple(
        (joinSteps(head, outer, prepared_slots), rollSteps(head_state, outer, prepared_slots), inner)
        for head, head_state, outer, inner in CROSS_VFTABLE
    )

    yield from containerHits(out_full, out_quals, out_full, out_quals)
    for fundamental in FUNDAMENTALS:
        yield from containerHits(out_full, out_quals, fundamental, ())
        yield from containerHits(fundamental, (), out_full, out_quals)

        slots = outer_slots + packSlots(CROSS_INNER_SLOTS, in_param=fundamental)
        for prefix, state, inner in prepared_functions:
            checksum = state
            for slot, static in inner:
                checksum = adler32(static, adler32(slots[slot], checksum))
            if checksum in hashes:
                yield (prefix + joinSteps(b'', inner, slots)).decode('utf-8'), 1

    for in_cls_key, in_decorated, in_quals, in_cls_decorated in found_classes:
        if in_decorated == out_decorated:
            continue

        if any(qual in out_quals for qual in in_quals):
            arg_quals = "".join(
                str(arg_refs.index(qual)) if qual in arg_refs else f"{qual}@"
                for qual in in_quals)
            param_quals = "".join(
                str(out_quals.index(qual)) if qual in out_quals else f"{qual}@"
                for qual in in_quals)
        else:
            arg_quals = param_quals = f"{in_decorated}@"

        if any(qual in connector_refs for qual in in_quals):
            connector_quals = "".join(
                str(connector_refs.index(qual)) if qual in connector_refs else f"{qual}@"
                for qual in in_quals)
        else:
            connector_quals = param_quals

        slots = outer_slots + packSlots(
            CROSS_INNER_SLOTS,
            in_param=f"{in_cls_key}{param_quals}@",
            in_arg=f"{in_cls_key}{arg_quals}",
            in_connector=f"{in_cls_key}{connector_quals}",
            in_cls_decorated=in_cls_decorated,
            in_param_quals=param_quals,
        )

        for prefix, state, inner in prepared_functions:
            checksum = state
            for slot, static in inner:
                checksum = adler32(static, adler32(slots[slot], checksum))
            if checksum in hashes:
                yield (prefix + joinSteps(b'', inner, slots)).decode('utf-8'), 1

        for prefix, state, inner in prepared_vftable:
            checksum = state
            for slot, static in inner:
                checksum = adler32(static, adler32(slots[slot], checksum))
            if checksum in hashes:
                yield (prefix + joinSteps(b'', inner, slots)).decode('utf-8'), 2

        yield from containerHits(out_full, out_quals, in_cls_decorated + "@@", in_quals)


def findCrossPairs(entry):
    return list(crossHits(entry))
'''


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
start()
try:
    current_program.setEventsEnabled(False)

    for cls_key, quals, native_type_hash_addr, native_type_hash_mangled in chain(
        resolving.resolveClassTypes(),
        resolving.resolveUniqueTypes(),
    ):
        quitIfCancelled()
        demangling.label(native_type_hash_addr, native_type_hash_mangled)

        decorated = '@'.join(quals)
        cls_decorated = f"{cls_key}{decorated}"
        found_classes.append((cls_key, decorated, quals, cls_decorated))

        copy_spec = ''
        for mangled, is_no_copy in (
            (f"??_7?$TNativeClass@{cls_decorated}@@@rtti@@6B@", False),
            (f"??_7?$TNativeClassNoCopy@{cls_decorated}@@@rtti@@6B@", True),
        ):
            if resolving.findMangledThenLabel(mangled, 2):
                if is_no_copy:
                    copy_spec = 'NoCopy'
                break

        slots = packSlots(
            SLOT_NAMES,
            decorated=decorated,
            cls_decorated=cls_decorated,
            cls_back_refs=f"{cls_key}{'0123456789'[:len(quals)]}",
            copy_spec=copy_spec,
            variant_index=str(len(quals) + 3),
        )

        for encoded in resolving.templateHits(CLASS_FUNCTIONS, slots):
            if resolving.findEncodedThenLabel(encoded, 1):
                resolving.labelUnwind(encoded)

        resolving.findMangledThenLabel(f"??_7{decorated}@@6B@", 2)

        for encoded in resolving.templateHits(CLASS_DATA, slots):
            resolving.findEncodedThenLabel(encoded, 3)

    for fundamental in FUNDAMENTALS:
        quitIfCancelled()
        slots = packSlots(SLOT_NAMES, fundamental=fundamental)

        for encoded in resolving.templateHits(FUNDAMENTAL_FUNCTIONS, slots):
            resolving.findEncodedThenLabel(encoded, 1)

        for encoded in resolving.templateHits(FUNDAMENTAL_DATA, slots):
            resolving.findEncodedThenLabel(encoded, 3)

    worker_dir = tempfile.mkdtemp(prefix='ghidra_cross_')
    with open(os.path.join(worker_dir, 'crossworker.py'), 'w') as handle:
        handle.write(CROSS_WORKER_SOURCE)
    sys.path.insert(0, worker_dir)
    sys.modules.pop('crossworker', None)
    import crossworker

    crossworker.configure((), frozenset(resolving.adler32_hashes), FUNDAMENTALS)
    for key_fundamental in FUNDAMENTALS:
        quitIfCancelled()
        for value_fundamental in FUNDAMENTALS:
            for mangled, block_idx in crossworker.containerHits(key_fundamental, (), value_fundamental, ()):
                resolving.findMangledThenLabel(mangled, block_idx)

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
        initargs=(found_classes, frozenset(resolving.adler32_hashes), FUNDAMENTALS),
    ) as executor:
        for hits in executor.map(crossworker.findCrossPairs, found_classes, chunksize=32):
            if monitor.isCancelled():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            for mangled, block_idx in hits:
                encoded = mangled.encode('utf-8')
                if resolving.findEncodedThenLabel(encoded, block_idx) and block_idx == 1:
                    resolving.labelUnwind(encoded)
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
    end(should_commit)
