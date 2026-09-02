using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace KotorKPatchAdapter.Tests
{
    internal static class SmokeTests
    {
        private const string SourceHashA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        private const string CustomHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        private const string SourceHashC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

        private static int Main()
        {
            string temp = Path.Combine(Path.GetTempPath(), "KotorKPatchAdapterTests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            try
            {
                TestGenericHooks(temp);
                TestVersionedHooks(temp);
                TestGenericNamedHooks(temp);
                TestDefaultDetourWithParameters(temp);
                TestMultiVersionSelection(temp);
                TestAmbiguousVersionBundlesAreBlocked(temp);
                Console.WriteLine("All KPatch adapter smoke tests passed.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return 1;
            }
            finally
            {
                try { Directory.Delete(temp, true); } catch { }
            }
        }

        private static void TestGenericHooks(string temp)
        {
            ExeAnalysis exe = MakeExe(
                new HookBytes(0x00401000, new byte[] { 0x10, 0x20 }));
            string hooks = SimpleHook(0x00401000, new byte[] { 0x10, 0x20 }, new byte[] { 0x30, 0x40 });
            string patch = CreatePatch(temp, "generic.kpatch",
                new[] { SourceHashA },
                new Dictionary<string, string> { { "hooks.toml", hooks } });

            PatchAnalysis analysis = AdapterCore.AnalyzePatch(patch, exe);
            Assert(analysis.Compatible, "Generic hooks.toml should be compatible: " + JoinErrors(analysis));
            Assert(analysis.HookFiles.SequenceEqual(new[] { "hooks.toml" }),
                "Generic hooks.toml was not selected.");

            string output = AdapterCore.ConvertPatch(analysis, exe);
            string manifest = ReadEntry(output, "manifest.toml");
            string convertedHooks = ReadEntry(output, "hooks.toml");
            Assert(manifest.Contains(SourceHashA), "Conversion removed the original supported hash.");
            Assert(manifest.Contains(CustomHash), "Conversion did not add the custom supported hash.");
            Assert(convertedHooks == hooks, "Generic hooks.toml should remain generic and byte-for-byte unchanged.");

            PatchAnalysis verified = AdapterCore.AnalyzePatch(output, exe);
            Assert(verified.Compatible && verified.AlreadySupportsHash,
                "Converted generic patch did not verify independently: " + JoinErrors(verified));
        }

        private static void TestVersionedHooks(string temp)
        {
            ExeAnalysis exe = MakeExe(
                new HookBytes(0x00401000, new byte[] { 0x10, 0x20 }));
            string hooks = Metadata(SourceHashA) + "\n" +
                SimpleHook(0x00401000, new byte[] { 0x10, 0x20 }, new byte[] { 0x30, 0x40 });
            string patch = CreatePatch(temp, "versioned.kpatch",
                new[] { SourceHashA },
                new Dictionary<string, string> { { "kotor1_103.hooks.toml", hooks } });

            PatchAnalysis analysis = AdapterCore.AnalyzePatch(patch, exe);
            Assert(analysis.Compatible, "Versioned KPM 0.6.3 hooks should be compatible: " + JoinErrors(analysis));

            string output = AdapterCore.ConvertPatch(analysis, exe);
            string manifest = ReadEntry(output, "manifest.toml");
            string convertedHooks = ReadEntry(output, "kotor1_103.hooks.toml");
            Assert(manifest.Contains(SourceHashA) && manifest.Contains(CustomHash),
                "Versioned conversion did not preserve and extend manifest hashes.");
            Assert(convertedHooks.Contains(SourceHashA) && convertedHooks.Contains(CustomHash),
                "Versioned conversion did not preserve and extend target_versions.");

            PatchAnalysis verified = AdapterCore.AnalyzePatch(output, exe);
            Assert(verified.Compatible && verified.AlreadySupportsHash,
                "Converted versioned patch did not verify independently: " + JoinErrors(verified));
        }

        private static void TestGenericNamedHooks(string temp)
        {
            ExeAnalysis exe = MakeExe(
                new HookBytes(0x00401000, new byte[] { 0x10, 0x20 }));
            string hooks = SimpleHook(0x00401000, new byte[] { 0x10, 0x20 }, new byte[] { 0x30, 0x40 });
            string patch = CreatePatch(temp, "generic-named.kpatch",
                new[] { SourceHashA },
                new Dictionary<string, string> { { "common.hooks.toml", hooks } });
            PatchAnalysis analysis = AdapterCore.AnalyzePatch(patch, exe);
            Assert(analysis.Compatible, "A generic file whose name ends in hooks.toml should be accepted: " + JoinErrors(analysis));
        }

        private static void TestDefaultDetourWithParameters(string temp)
        {
            ExeAnalysis exe = MakeExe(
                new HookBytes(0x00401000, new byte[] { 1, 2, 3, 4, 5 }));
            string hooks =
                "[[hooks]]\n" +
                "address = 0x00401000\n" +
                "function = \"HookFunction\"\n" +
                "original_bytes = [1, 2, 3, 4, 5]\n" +
                "\n[[hooks.parameters]]\n" +
                "source = \"esi\"\n" +
                "type = \"pointer\"\n";
            string patch = CreatePatch(temp, "default-detour.kpatch",
                new[] { SourceHashA },
                new Dictionary<string, string> { { "hooks.toml", hooks } });
            PatchAnalysis analysis = AdapterCore.AnalyzePatch(patch, exe);
            Assert(analysis.Compatible,
                "A missing main hook type should default to detour even when a nested parameter has type=pointer: " + JoinErrors(analysis));
            Assert(analysis.Hooks.Count == 1 && analysis.Hooks[0].HookType == "detour",
                "The default hook type was not detour.");
        }

        private static void TestMultiVersionSelection(string temp)
        {
            ExeAnalysis exe = MakeExe(
                new HookBytes(0x00401000, new byte[] { 0x10, 0x20 }),
                new HookBytes(0x00401010, new byte[] { 1, 2, 3, 4, 5 }));

            string generic = SimpleHook(0x00401000, new byte[] { 0x10, 0x20 }, new byte[] { 0x30, 0x40 });
            string versionA = Metadata(SourceHashA) + "\n" +
                DetourHook(0x00401010, "VersionAHook", new byte[] { 1, 2, 3, 4, 5 });
            string versionC = Metadata(SourceHashC) + "\n" +
                DetourHook(0x00401010, "VersionCHook", new byte[] { 9, 9, 9, 9, 9 });

            string patch = CreatePatch(temp, "multi-version.kpatch",
                new[] { SourceHashA, SourceHashC },
                new Dictionary<string, string>
                {
                    { "hooks.toml", generic },
                    { "windows-a.hooks.toml", versionA },
                    { "windows-c.hooks.toml", versionC }
                });

            PatchAnalysis analysis = AdapterCore.AnalyzePatch(patch, exe);
            Assert(analysis.Compatible, "The matching complete version bundle should be selected: " + JoinErrors(analysis));
            Assert(analysis.HookFiles.Contains("hooks.toml") && analysis.HookFiles.Contains("windows-a.hooks.toml"),
                "The generic plus matching version-specific files were not selected.");
            Assert(!analysis.HookFiles.Contains("windows-c.hooks.toml"),
                "The nonmatching alternate version file should not be selected.");

            string output = AdapterCore.ConvertPatch(analysis, exe);
            Assert(ReadEntry(output, "hooks.toml") == generic, "Generic hooks changed during multi-version conversion.");
            Assert(ReadEntry(output, "windows-a.hooks.toml").Contains(CustomHash),
                "The custom hash was not added to the selected version file.");
            Assert(!ReadEntry(output, "windows-c.hooks.toml").Contains(CustomHash),
                "The custom hash was incorrectly added to an unselected alternate version file.");

            PatchAnalysis verified = AdapterCore.AnalyzePatch(output, exe);
            Assert(verified.Compatible && verified.AlreadySupportsHash,
                "Converted multi-version patch did not verify independently: " + JoinErrors(verified));
        }

        private static void TestAmbiguousVersionBundlesAreBlocked(string temp)
        {
            ExeAnalysis exe = MakeExe(
                new HookBytes(0x00401010, new byte[] { 1, 2, 3, 4, 5 }),
                new HookBytes(0x00401020, new byte[] { 6, 7, 8, 9, 10 }));

            string versionA = Metadata(SourceHashA) + "\n" +
                DetourHook(0x00401010, "VersionAHook", new byte[] { 1, 2, 3, 4, 5 });
            string versionC = Metadata(SourceHashC) + "\n" +
                DetourHook(0x00401020, "VersionCHook", new byte[] { 6, 7, 8, 9, 10 });

            string patch = CreatePatch(temp, "ambiguous.kpatch",
                new[] { SourceHashA, SourceHashC },
                new Dictionary<string, string>
                {
                    { "version-a.hooks.toml", versionA },
                    { "version-c.hooks.toml", versionC }
                });

            PatchAnalysis analysis = AdapterCore.AnalyzePatch(patch, exe);
            Assert(!analysis.Compatible, "Distinct version-specific bundles that both match must be blocked.");
            Assert(analysis.Errors.Any(x => x.IndexOf("ambiguous", StringComparison.OrdinalIgnoreCase) >= 0),
                "The ambiguous bundle failure was not reported clearly: " + JoinErrors(analysis));
        }

        private static string Metadata(string hash)
        {
            return
                "[metadata]\n" +
                "target_versions = [\n" +
                "    \"" + hash + "\"\n" +
                "]\n";
        }

        private static string SimpleHook(ulong address, byte[] original, byte[] replacement)
        {
            return
                "[[hooks]]\n" +
                "address = 0x" + address.ToString("X8") + "\n" +
                "type = \"simple\"\n" +
                "original_bytes = [" + ByteList(original) + "]\n" +
                "replacement_bytes = [" + ByteList(replacement) + "]\n";
        }

        private static string DetourHook(ulong address, string function, byte[] original)
        {
            return
                "[[hooks]]\n" +
                "address = 0x" + address.ToString("X8") + "\n" +
                "type = \"detour\"\n" +
                "function = \"" + function + "\"\n" +
                "original_bytes = [" + ByteList(original) + "]\n";
        }

        private static string ByteList(byte[] bytes)
        {
            return string.Join(", ", bytes.Select(x => "0x" + x.ToString("X2")).ToArray());
        }

        private static ExeAnalysis MakeExe(params HookBytes[] hookBytes)
        {
            byte[] data = new byte[0x1200];
            foreach (HookBytes hook in hookBytes)
            {
                int rawOffset = 0x200 + checked((int)(hook.Address - 0x00401000));
                Buffer.BlockCopy(hook.Bytes, 0, data, rawOffset, hook.Bytes.Length);
            }

            PEInfo pe = new PEInfo
            {
                Machine = 0x14C,
                Architecture = "x86",
                ImageBase = 0x00400000,
                SizeOfHeaders = 0x200,
                Characteristics = 0,
                LargeAddressAware = false
            };
            pe.Sections.Add(new PESection
            {
                Name = ".text",
                VirtualAddress = 0x1000,
                VirtualSize = 0x1000,
                RawOffset = 0x200,
                RawSize = 0x1000,
                Characteristics = 0x60000020
            });

            return new ExeAnalysis
            {
                Path = "synthetic.exe",
                Sha256 = CustomHash,
                FileSize = data.LongLength,
                Data = data,
                PE = pe
            };
        }

        private static string CreatePatch(
            string temp,
            string fileName,
            IEnumerable<string> supportedHashes,
            IDictionary<string, string> hookFiles)
        {
            string path = Path.Combine(temp, fileName);
            using (FileStream stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            using (ZipArchive archive = new ZipArchive(stream, ZipArchiveMode.Create))
            {
                StringBuilder manifest = new StringBuilder();
                manifest.AppendLine("[patch]");
                manifest.AppendLine("id = \"test-patch\"");
                manifest.AppendLine("name = \"Test Patch\"");
                manifest.AppendLine("version = \"1.0.0\"");
                manifest.AppendLine("author = \"Tests\"");
                manifest.AppendLine("description = \"Test\"");
                manifest.AppendLine("requires = []");
                manifest.AppendLine("conflicts = []");
                manifest.AppendLine();
                manifest.AppendLine("[patch.supported_versions]");
                int index = 0;
                foreach (string hash in supportedHashes)
                {
                    index++;
                    manifest.AppendLine("source_" + index + " = \"" + hash + "\"");
                }
                WriteEntry(archive, "manifest.toml", manifest.ToString());
                foreach (KeyValuePair<string, string> file in hookFiles)
                    WriteEntry(archive, file.Key, file.Value);
            }
            return path;
        }

        private static void WriteEntry(ZipArchive archive, string name, string content)
        {
            ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.Optimal);
            using (Stream stream = entry.Open())
            using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false)))
                writer.Write(content);
        }

        private static string ReadEntry(string archivePath, string name)
        {
            using (FileStream stream = File.OpenRead(archivePath))
            using (ZipArchive archive = new ZipArchive(stream, ZipArchiveMode.Read))
            {
                ZipArchiveEntry entry = archive.GetEntry(name);
                if (entry == null) throw new InvalidOperationException("Missing archive entry: " + name);
                using (Stream entryStream = entry.Open())
                using (StreamReader reader = new StreamReader(entryStream, Encoding.UTF8, true))
                    return reader.ReadToEnd();
            }
        }

        private static string JoinErrors(PatchAnalysis analysis)
        {
            return string.Join(" | ", analysis.Errors.Concat(analysis.Warnings).ToArray());
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
        }

        private sealed class HookBytes
        {
            public HookBytes(ulong address, byte[] bytes)
            {
                Address = address;
                Bytes = bytes;
            }

            public ulong Address { get; private set; }
            public byte[] Bytes { get; private set; }
        }
    }
}
