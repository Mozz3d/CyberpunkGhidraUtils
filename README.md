# CyberpunkGhidraUtils

A collection of Ghidra scripts for reverse engineering Cyberpunk 2077 (Windows x64).

Cyberpunk 2077 ships a linker-derived (Adler32/SHA256) hash-address map (`cyberpunk2077_addresses.json`).
Naturally this means hashes are derived from the decorated names of symbols emitted by the compiler, which the linker reads and maps.

By understanding how the compiler decorates names, these scripts build templates which are ran across information found in the binary
to identify source data and its location.

---

## Requirements

- **Completed auto-analysis**.
- **PyGhidra** (bundled since Ghidra 11.3)
- **`cyberpunk2077_addresses.json`** from the **same version** as the relevant executable.

---

## Installation

Drop the relevant file(s) into your Ghidra scripts directory, by default:

```
C:\Users\<user>\ghidra_scripts
```

They can then be found in Ghidra under the **Cyberpunk** category in the **Script Manager**.

---

## Usage

### One shot

Run **`CyberpunkOneShotAnalyze.py`**. It imports hashes, then derives strings and RTTI symbols, all in a single transaction.

### Stepwise

First **`CyberpunkSymbolHashImport.py`**:

The derivers read hashes back out of the plate comments the importer writes, 
therefore it must be run **and committed** first.

Attempts to locate `cyberpunk2077_addresses.json` automatically, if not then you must direct it.

Second **`CyberpunkStringDeriver.py`**:

Deriving strings first makes identifying class names more consistent,
therefore this is best run before the RTTI deriver.

Lastly **`CyberpunkRTTIDeriver.py`**:

The most prolific of the scripts, best run last as it requires information from the others.

---

## Troubleshooting

| Message | Cause |
| --- | --- |
| `Please analyze the program first, exiting` | Auto-analysis hasn't run, or is still running. |
| `Could not find 'cyberpunk2077_addresses.json'` | Not beside the executable — pick it via the chooser. |
| `File selected is not 'cyberpunk2077_addresses.json'` | The filename must match exactly. |
| `Could not locate 'rtti::ClassType::ClassType', are hashes imported?` | Run `CyberpunkSymbolHashImport.py` first, on this program, and let it commit. |

Symbols landing at wrong or nonsensical addresses almost always means the JSON is from a different version
than the imported executable, or the memory block layout was altered after import.
