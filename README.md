# KOTOR KPatch Adapter

KOTOR KPatch Adapter is a small Windows tool for people who use **KotOR Patch Manager** with a modified `swkotor.exe`.

Some KOTOR mods change the game executable for things like widescreen resolutions or the 4 GB patch. Even when those changes do not touch the code a `.kpatch` needs, Patch Manager may reject the EXE because its SHA-256 hash no longer matches a version the patch knows about.

This tool checks whether the patch still matches your actual EXE. If it does, it can make an adapted copy of the `.kpatch` for that EXE and update Patch Manager's existing KOTOR 1 address database so the new hash is recognized.

## Download

Download the latest Windows build from the [Releases page](https://github.com/gnw-d3m0/Kotor-KPatch-Adapter/releases/latest).

You can download `KotorKPatchAdapter.exe` directly, or use the release ZIP if you also want a copy of the README and license.

No build script is needed to use the program.

## Patch Manager compatibility

Version 0.2.0 supports the Windows releases of **KotOR Patch Manager 0.6.2 and 0.6.3**.

It recognizes the hook layouts used by 0.6.3, including:

- generic root-level `hooks.toml` files with no `[metadata]` table
- version-filtered files such as `kotor1_103.hooks.toml`
- any other archive entry whose file name ends in `hooks.toml`
- patches with several hook files for different game versions

The adapter mirrors Patch Manager 0.6.3's selection rules. A hook file with no `target_versions`, or an empty list, is generic and applies to every version listed by the manifest. Version-filtered files are grouped by their `target_versions`, and only a complete bundle whose original bytes match the selected EXE can be adapted.

Generic files are left generic. For version-filtered files, the new EXE hash is added only to the verified matching bundle; alternate hook files for other game versions are left unchanged.

## What it does

You select:

- your current `swkotor.exe`
- your KotOR Patch Manager folder
- one or more `.kpatch` files

Then click **Analyze Compatibility**.

The adapter checks the selected EXE and every hook that Patch Manager would load for a candidate source version. It compares the patch's expected `original_bytes` with the bytes that are actually present at the required virtual addresses.

If one complete hook bundle matches, the patch is considered safe to adapt. If multiple distinct bundles match, conversion is blocked rather than guessing which version-specific implementation should be used.

When you click **Convert & Update Patch Manager**, the tool:

- creates adapted copies of the selected `.kpatch` files
- adds the SHA-256 of your current EXE to each copied manifest
- adds that hash to the selected version-specific hook metadata when required
- leaves generic `hooks.toml` files unfiltered
- backs up `kotor1_0_3.db`
- updates the existing `kotor1_0_3.db` in place so Patch Manager recognizes your EXE
- runs an SQLite integrity check after the database update
- leaves `swkotor.exe` itself untouched

Existing manifest hashes and existing hook target hashes are preserved in the adapted copy.

## Why this is useful

A modified EXE does not automatically mean a KPatch is incompatible.

For example, a widescreen patch may only change resolution-related bytes, while a KPatch may hook a completely different part of the game. The EXE hash changes either way, so Patch Manager can reject it even though the code needed by the patch is still intact.

KOTOR KPatch Adapter checks the part that actually matters: whether the patch's required hook bytes are still present where the patch expects them.

## When conversion is allowed

Automatic conversion is only enabled when every required hook in one complete Patch Manager hook bundle matches the current EXE.

This means changes such as these can often be adapted safely when they do not touch the patch's hook locations:

- UniWS and other widescreen changes
- custom resolution patches
- 4 GB flag changes
- PE checksum changes
- unrelated executable tweaks

The adapter also checks for overlapping hooks when several `.kpatch` files are selected together.

## When conversion is blocked

If another executable modification changed code that a `.kpatch` depends on, the adapter refuses to convert it automatically.

It may report that the expected byte sequence exists somewhere else in the EXE, but it will **not** automatically move the hook. A relocated hook can require more than changing one address, especially when injected code or replacement logic contains address-dependent assumptions.

Conversion is also blocked when more than one distinct version-specific hook bundle fully matches. That situation needs manual review because adding the custom hash to every matching bundle would make Patch Manager load duplicate or conflicting hooks.

## How to use it

1. Run `KotorKPatchAdapter.exe`.
2. Select your current `swkotor.exe`.
3. Select the **root folder** of KotOR Patch Manager — the folder that contains the `bin`, `patches`, and `tools` folders. You can also select the `bin` folder directly.
4. Add the `.kpatch` file or files you want to check.
5. Click **Analyze Compatibility**.
6. Read the selected hook files and result for each patch.
7. If the tool reports that everything is compatible, click **Convert & Update Patch Manager**.

For KotOR Patch Manager 0.6.3, the folder layout looks like this:

```text
KotorPatchManager-v0.6.3/
├─ bin/
│  ├─ AddressDatabases/
│  │  └─ kotor1_0_3.db
│  ├─ KotorPatcher.dll
│  ├─ KPatchLauncher.exe
│  └─ sqlite3.dll
├─ patches/
│  └─ your-patches.kpatch
├─ tools/
│  └─ create-patch.bat
└─ README.txt
```

The important files for this adapter are:

```text
bin\sqlite3.dll
bin\AddressDatabases\kotor1_0_3.db
```

Converted `.kpatch` files are created next to the original patch files you selected. You can then place them in Patch Manager's `patches` folder if they are not already there.

## Database backups

Before changing `kotor1_0_3.db`, the adapter creates a timestamped backup next to it, for example:

```text
kotor1_0_3.db.bak-20260901-221500
```

If the database update fails, the program attempts to restore that backup automatically.

## Building from source

The project is written in C# using Windows Forms and targets **.NET Framework 4.8 / x86**.

The x86 target is intentional because KotOR Patch Manager ships with a 32-bit `sqlite3.dll`.

To build it yourself, open `KotorKPatchAdapter.csproj` in Visual Studio with the .NET Framework 4.8 developer tools installed and build **Release / x86**.

Release builds are compiled automatically on GitHub Actions, so normal users do not need Visual Studio or any build tools.

## Current limitations

- KOTOR 1 Windows x86 only
- designed for KotOR Patch Manager 0.6.2 and 0.6.3
- checks `simple`, `replace`, `detour`, and `static` hooks
- does not automatically relocate moved hooks
- blocks ambiguous matches between distinct version-specific hook bundles
- does not rebuild address tables for an EXE whose code layout has actually been rearranged
- uses Patch Manager's existing `bin\sqlite3.dll`

## Safety

The adapter does not patch or rewrite `swkotor.exe`.

Its job is to verify compatibility, create adapted `.kpatch` copies, and update Patch Manager's version recognition database. If the required hook data does not match, automatic conversion is blocked instead of guessing.
