# KOTOR KPatch Adapter

KOTOR KPatch Adapter is a small Windows tool for people who use **KotOR Patch Manager** with a modified `swkotor.exe`.

Some KOTOR mods change the game executable for things like widescreen resolutions or the 4 GB / Large Address Aware flag. Even when those changes do not touch the code a `.kpatch` needs, Patch Manager may reject the EXE because its SHA-256 hash no longer matches a version the patch knows about.

This tool checks whether the patch still matches your actual EXE. If it does, it can make a converted copy of the `.kpatch` for that EXE and update Patch Manager's existing KOTOR 1 address database so the new hash is recognized.

## What it does

You select:

- your current `swkotor.exe`
- your Kotor Patch Manager folder
- one or more `.kpatch` files

Then click **Analyze Compatibility**.

The adapter checks the selected EXE and every hook used by the patch. It compares the patch's expected `original_bytes` with the bytes that are actually present at the required addresses.

If everything still matches, the patch is considered safe to adapt.

When you click **Convert & Update Patch Manager**, the tool:

- creates converted copies of the selected `.kpatch` files
- makes those copies target the SHA-256 of your current EXE
- backs up `kotor1_0_3.db`
- updates the existing `kotor1_0_3.db` in place so Patch Manager recognizes your EXE
- runs an SQLite integrity check after the database update
- leaves `swkotor.exe` itself untouched

## Why this is useful

A modified EXE does not automatically mean a KPatch is incompatible.

For example, a widescreen patch may only change resolution-related bytes, while a KPatch may hook a completely different part of the game. The EXE hash changes either way, so Patch Manager can reject it even though the code needed by the patch is still intact.

KOTOR KPatch Adapter checks the part that actually matters: whether the patch's required hook bytes are still present where the patch expects them.

## When conversion is allowed

Automatic conversion is only enabled when every required hook matches the current EXE.

This means changes such as these can often be adapted safely when they do not touch the patch's hook locations:

- UniWS and other widescreen changes
- custom resolution patches
- Large Address Aware / 4 GB flag changes
- PE checksum changes
- unrelated executable tweaks

The adapter also checks for overlapping hooks when several `.kpatch` files are selected together.

## When conversion is blocked

If another executable modification changed code that a `.kpatch` depends on, the adapter refuses to convert it automatically.

It may report that the expected byte sequence exists somewhere else in the EXE, but it will **not** automatically move the hook. A relocated hook can require more than changing one address, especially when injected code or replacement logic contains address-dependent assumptions.

In that situation the patch needs manual review.

## How to use it

1. Run `KotorKPatchAdapter.exe`.
2. Select your current `swkotor.exe`.
3. Select the root folder of Kotor Patch Manager. This is the folder that contains `sqlite3.dll`.
4. Add the `.kpatch` file or files you want to check.
5. Click **Analyze Compatibility**.
6. Read the result for each patch.
7. If the tool reports that everything is compatible, click **Convert & Update Patch Manager**.

The Patch Manager folder should contain paths like these:

```text
Kotor Patch Manager/
├─ sqlite3.dll
└─ bin/
   └─ AddressDatabases/
      └─ kotor1_0_3.db
```

## Database backups

Before changing `kotor1_0_3.db`, the adapter creates a timestamped backup next to it, for example:

```text
kotor1_0_3.db.bak-20260829-221500
```

If the database update fails, the program attempts to restore that backup automatically.

## Building from source

The project is written in C# using Windows Forms and targets **.NET Framework 4.8 / x86**.

The x86 target is intentional because Kotor Patch Manager ships with a 32-bit `sqlite3.dll`.

### Quick build

On Windows, double-click:

```text
Build_EXE.bat
```

The script looks for the .NET Framework C# compiler and builds:

```text
KotorKPatchAdapter.exe
```

If the compiler is not available, open `KotorKPatchAdapter.csproj` in Visual Studio with the .NET Framework 4.8 developer tools installed and build the project as **Release / x86**.

## Current limitations

- KOTOR 1 Windows x86 only
- designed for the current Kotor Patch Manager `.kpatch` format
- checks `simple`, `replace`, `detour`, and `static` hooks
- does not automatically relocate moved hooks
- does not rebuild address tables for an EXE whose code layout has actually been rearranged
- uses Patch Manager's existing `sqlite3.dll`

## Safety

The adapter does not patch or rewrite `swkotor.exe`.

Its job is to verify compatibility, create adapted `.kpatch` copies, and update Patch Manager's version recognition database. If the required hook data does not match, automatic conversion is blocked instead of guessing.
