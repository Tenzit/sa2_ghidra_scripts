# SA2 Ghidra Scripts

A set of Ghidra scripts for automating SA2 decomp stuff

## Usage

### In Ghidra

1. Open your project.  
2. **Window → Script Manager**.  
3. Add this repo’s folder to the script directories.  
4. Select a script → **Run**.  
   If the script takes arguments, Ghidra will prompt for them.

### Headless mode

(Untested)

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
  /path/to/project  ProjectName \
  -scriptPath ./scripts \
  -postScript <script>.py <args>
```

Arguments after the script name are passed directly to the script.

## Script Catalog

| Script | Description | Key Args | Notes |
|---|---|---|---|
| `AliasFunctions.py` | Aliases functions in mirrored dreamcast ranges to the 0x8xxxxxxx range | `<block> <delta>` | |
| `ClassifyFunctions.py` | Classifies functions by reachability from a chosen root function | `<Function under cursor>`| Prompts for output `.csv` file |
| `Dump.py` | Exports the current function to a c file | `<Fuction under cursor>` | Prompts for output directory |
| `GetDataTypeUses.py` | Finds all structures that use a given datatype | `<datatype path>` | Prints to console |
| `GetLevelSetDescriptorInfo.py` | Used to get information about what SetFileDescriptor elements exist and are used/unique| | |
| `HandleObjectThreshold.py` | Checks for `object_delete_if_past_distance_threshold` and a local copy of `action_struct` being assigned and sets some default variable names for those checks | | Not perfect, uses decomp to figure out information which isn't 100% accurate |
| `PrintData.py` | Recursively prints data under cursor | | |
| `SetObjectInitEdit.py` | Used to set up `<Object>_new/init` functions, defining the objects, `update/delete/display` functions, custom datatypes, and some other things | | |

## Helpers

| Helper | Description |
|---|---|
| `GhidraUtils.py` | Used for parsing clang tokens, mostly. Used in `HandleObjectThreshold.py` and `SetObjectInitEdit.py` |
| `GhidraArgumentParser.py` | Contains a custom `GhidraArgumentParser` that allows you to pass in args via command line or be prompted for args if you're running in GUI |

## Compatibility

- Tested with PyGhidra on **Ghidra 11.x** for most scripts
- Tested with Jython on **Ghidra 10.x** for ones with `#@runtime jython`