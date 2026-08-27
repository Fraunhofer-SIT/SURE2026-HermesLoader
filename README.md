# hermesloader

Hermes bytecode loader and language extension for Ghidra, including analyzer passes for indirect-call recovery and function/string reference analysis.

## Requirements

- Java Development Kit (JDK) 21
- Ghidra (tested with 11.4.1)
- Gradle wrapper included in this repository root (`gradlew`, `gradlew.bat`)

The Ghidra extension project lives in `hermesloader/`.

## Build

Set the Ghidra installation path through `GHIDRA_INSTALL_DIR`, then build the extension zip.

### Windows (PowerShell)

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_11.4.1_PUBLIC"
Set-Location hermesloader
..\gradlew.bat clean buildExtension
```

### Linux / macOS

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.1_PUBLIC
cd hermesloader
../gradlew clean buildExtension
```

Build artifacts are written to `hermesloader/dist/`.

## Install in Ghidra

1. Start Ghidra.
2. Open `File -> Install Extensions...`.
3. Click `+` and select the extension zip from `hermesloader/dist/`.
4. Restart Ghidra when prompted.

## Development Setup

For local development, ensure your IDE and Gradle use JDK 21.

Install GhidraDev.

Link Ghidra: Right click on the projekt in Eclipse, "GhidraDev" > "Link Ghidra..."

### Using gradle.properties.sample

If you prefer file-based configuration to environment variables:

1. Copy `hermesloader/gradle.properties.sample` to `hermesloader/gradle.properties`.
2. Update `GHIDRA_INSTALL_DIR` to your local Ghidra installation path.
3. Update `org.gradle.java.home` to your local JDK 21 path.

Examples:

```powershell
Copy-Item hermesloader/gradle.properties.sample hermesloader/gradle.properties
```

```bash
cp hermesloader/gradle.properties.sample hermesloader/gradle.properties
```

Only one location is required for `GHIDRA_INSTALL_DIR`: either the environment variable or `gradle.properties`.

- Run a full build: `cd hermesloader && ../gradlew build` or `Set-Location hermesloader; ..\gradlew.bat build`
- Build installable package: `cd hermesloader && ../gradlew buildExtension` or `Set-Location hermesloader; ..\gradlew.bat buildExtension`

If Gradle cannot find Ghidra, confirm `GHIDRA_INSTALL_DIR` points to the Ghidra root directory (the folder containing `support/buildExtension.gradle`).

## Loaded Data Regions

The loader reconstructs helper regions at fixed base addresses:

- String Data Base: `0x0A000000` (ram)
- String Table Base: `0xA0000000` (ram)
- Loaded Function Table Base: `0xF0000000` (ram)

Note: Although the SLEIGH spec defines separate spaces (`stringData`, `stringTable`), the current loader implementation allocates all three helper blocks in the default RAM address space.

These constants come from `HermesLoader` when creating the blocks.

## Lifter

The Hermes lifter is implemented through SLEIGH language specifications plus custom p-code inject payloads.

### Core Language Specs

- [hermesloader/data/languages/hermes_v96.slaspec](hermesloader/data/languages/hermes_v96.slaspec) (main instruction semantics)
- [hermesloader/data/languages/opcodes.slaspec](hermesloader/data/languages/opcodes.slaspec) (opcode definitions)
- [hermesloader/data/languages/opcodes_builtins.slaspec](hermesloader/data/languages/opcodes_builtins.slaspec) (builtin opcode semantics)
- [hermesloader/data/languages/type_tokens.slaspec](hermesloader/data/languages/type_tokens.slaspec) (token/type definitions)
- [hermesloader/data/languages/8Bit_register_tokens.slaspec](hermesloader/data/languages/8Bit_register_tokens.slaspec)
- [hermesloader/data/languages/32Bit_register_tokens.slaspec](hermesloader/data/languages/32Bit_register_tokens.slaspec)

### Language Configuration

- [hermesloader/data/languages/hermes_v96.ldefs](hermesloader/data/languages/hermes_v96.ldefs)
- [hermesloader/data/languages/hermes_v96.pspec](hermesloader/data/languages/hermes_v96.pspec)
- [hermesloader/data/languages/hermes_v96.cspec](hermesloader/data/languages/hermes_v96.cspec)
- [hermesloader/data/languages/hermes_v96.opinion](hermesloader/data/languages/hermes_v96.opinion)

### P-code Injects

- [hermesloader/src/main/java/hermesloader/inject/HermesInjectLibrary.java](hermesloader/src/main/java/hermesloader/inject/HermesInjectLibrary.java)
- [hermesloader/src/main/java/hermesloader/inject/InjectPayloadHermesGetById.java](hermesloader/src/main/java/hermesloader/inject/InjectPayloadHermesGetById.java)
- [hermesloader/src/main/java/hermesloader/inject/InjectPayloadHermesNewArrayWithBuffer.java](hermesloader/src/main/java/hermesloader/inject/InjectPayloadHermesNewArrayWithBuffer.java)
- [hermesloader/src/main/java/hermesloader/inject/InjectPayloadHermesNewObjectWithBuffer.java](hermesloader/src/main/java/hermesloader/inject/InjectPayloadHermesNewObjectWithBuffer.java)

### Loader Integration

- [hermesloader/src/main/java/hermesloader/HermesLoader.java](hermesloader/src/main/java/hermesloader/HermesLoader.java)

## Analyzers

This extension now provides three analyzers that appear in Ghidra's Analysis Options when a Hermes language program is loaded:

### Hermes Function Reference Summary (`HermesLoaderAnalyzer`)
Decompiler-assisted pass that:
* Gathers closure references via `PTRSUB` patterns.
* Builds heatmap entries for `getById` chains.
* Optionally traces indirect calls and their CALLOTHER origins.

### Hermes Function Coverage (`HermesLoaderFunctionCoverageAnalyzer`)
Lightweight instruction-level pass (no decompilation) that:
* Counts referenced vs unreferenced functions.
* Tallies resolved call instructions (function entry vs non-function vs unresolved).
* Optionally tracks CALLOTHER usage frequency (user-defined ops like `getById`, `putById`).

### Enabling / Configuring
Open: `Analysis -> Auto Analyze -> Options...` and locate each analyzer by name. They can run together. Coverage is fast and can give an overview before the heavier decompile-based analyzer.

Options for Hermes Function Coverage:
* Include Thunk Functions (default: false)
* Include External Functions (default: false)
* Track CALLOTHER Usage (default: true)
* Min Incoming Call Threshold To Report Individually (default: 1)

### Output
Both analyzers print detailed summaries to the Ghidra console and add a concise summary to the Message Log. CALLOTHER usage lines are sorted by ascending count for quick spotting of rarely used operations.

### Extensibility
Shared helper routines currently live in `HermesLoaderAnalyzer`. If more analyzers are added, consider extracting them into a small `HermesAnalysisUtil` class for reuse to avoid duplication.

### Hermes Missing Call Xrefs (`HermesLoaderMissingCallXrefAnalyzer`)
Purpose-built pass to recover missing call references for indirect calls whose targets can be conservatively resolved:
* Scans CALLIND pcode ops on call instructions with zero resolved flows.
* Traces shallow producer chains (COPY / CAST / INDIRECT) to find a constant/address.
* If the address matches a known function entry and no call reference exists, adds an `UNCONDITIONAL_CALL` xref.
* Options:
  * Enable Missing Call Xref Recovery (default: on)
  * Max Producer Trace Depth (default: 8)
  * Verbose Logging (default: off)
* Summary counts (recovered, already existing, failures) are printed to console and added to Message Log.

This analyzer should generally run after basic disassembly and function creation but before any advanced call graph metrics relying on complete incoming reference sets.