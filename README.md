# KOTOR KPatch Adapter

KOTOR KPatch Adapter is a Windows tool for adapting compatible `.kpatch` files to a modified KOTOR 1 `swkotor.exe`.

Mods such as widescreen fixes or the 4 GB patch change the EXE's hash. KotOR Patch Manager may then reject patches even when the code they need is still unchanged. This tool checks the patch against your actual EXE before creating an adapted copy.

It does **not** modify `swkotor.exe`.

## Download

Download the latest Windows build from the [Releases page](https://github.com/gnw-d3m0/Kotor-KPatch-Adapter/releases/latest).

You can download `KotorKPatchAdapter.exe` directly or use the release ZIP.

## Compatibility

The adapter supports KOTOR 1 on Windows with **KotOR Patch Manager 0.6.2 and 0.6.3**.

It supports both older `.kpatch` layouts and newer patches that use generic or version-specific hook files.

## How it works

The adapter compares every required hook with the bytes in your selected EXE. Conversion is allowed only when the patch still matches safely.

When a patch is converted, the tool:

- creates an adapted copy next to the original `.kpatch`
- adds support for the selected EXE while keeping the patch's existing version support
- backs up and updates Patch Manager's KOTOR 1 address database
- leaves the game EXE unchanged

If a required hook has been changed or the result is ambiguous, conversion is blocked instead of guessed.

## How to use

1. Run `KotorKPatchAdapter.exe`.
2. Select your current `swkotor.exe`.
3. Select your KotOR Patch Manager folder. You can select either the main folder or its `bin` folder.
4. Add one or more `.kpatch` files.
5. Click **Analyze Compatibility**.
6. Review the result.
7. Click **Convert & Update Patch Manager** when conversion is available.

The converted patches are saved beside the original files. Place them in Patch Manager's `patches` folder if needed.

Before the database is changed, the adapter creates a timestamped backup beside `kotor1_0_3.db`.

## Limitations

- KOTOR 1 Windows x86 only
- all required hook bytes must still match
- moved hooks are not relocated automatically
- overlapping or ambiguous hooks are blocked

## Building from source

The project uses C# Windows Forms and targets **.NET Framework 4.8 / x86**.

Open `KotorKPatchAdapter.csproj` in Visual Studio and build the **Release / x86** configuration.
