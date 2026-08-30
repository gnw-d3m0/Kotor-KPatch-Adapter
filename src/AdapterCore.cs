using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace KotorKPatchAdapter
{
    internal static class AdapterCore
    {
        public const string Version = "0.1.0";
        public const string ToolMarker = "KPatch Adapter:";
        public const string CustomVersionKey = "kotor1_current_custom_103";

        private static readonly HashSet<string> SupportedHookTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "simple", "replace", "detour", "static"
        };

        public static string ComputeSha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("X2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        private static ushort U16(byte[] data, int offset)
        {
            if (offset < 0 || offset + 2 > data.Length) throw new AdapterException("Unexpected end of executable while parsing PE headers.");
            return BitConverter.ToUInt16(data, offset);
        }

        private static uint U32(byte[] data, int offset)
        {
            if (offset < 0 || offset + 4 > data.Length) throw new AdapterException("Unexpected end of executable while parsing PE headers.");
            return BitConverter.ToUInt32(data, offset);
        }

        private static ulong U64(byte[] data, int offset)
        {
            if (offset < 0 || offset + 8 > data.Length) throw new AdapterException("Unexpected end of executable while parsing PE headers.");
            return BitConverter.ToUInt64(data, offset);
        }

        public static ExeAnalysis AnalyzeExe(string path)
        {
            byte[] data = File.ReadAllBytes(path);
            if (data.Length < 0x100 || data[0] != (byte)'M' || data[1] != (byte)'Z')
                throw new AdapterException("Selected file is not a valid PE/MZ executable.");

            int eLfanew = checked((int)U32(data, 0x3C));
            if (eLfanew < 0 || eLfanew + 24 > data.Length ||
                data[eLfanew] != (byte)'P' || data[eLfanew + 1] != (byte)'E' ||
                data[eLfanew + 2] != 0 || data[eLfanew + 3] != 0)
                throw new AdapterException("Selected file does not contain a valid PE header.");

            int coff = eLfanew + 4;
            ushort machine = U16(data, coff);
            ushort sectionCount = U16(data, coff + 2);
            ushort optionalSize = U16(data, coff + 16);
            ushort characteristics = U16(data, coff + 18);
            int opt = coff + 20;
            if (opt + optionalSize > data.Length) throw new AdapterException("PE optional header is truncated.");

            ushort magic = U16(data, opt);
            ulong imageBase;
            uint sizeHeaders;
            string arch;
            if (magic == 0x10B)
            {
                imageBase = U32(data, opt + 28);
                sizeHeaders = U32(data, opt + 60);
                arch = machine == 0x14C ? "x86" : "PE32 machine 0x" + machine.ToString("X4");
            }
            else if (magic == 0x20B)
            {
                imageBase = U64(data, opt + 24);
                sizeHeaders = U32(data, opt + 60);
                arch = machine == 0x8664 ? "x64" : "PE32+ machine 0x" + machine.ToString("X4");
            }
            else
            {
                throw new AdapterException("Unsupported PE optional-header magic 0x" + magic.ToString("X4") + ".");
            }

            PEInfo pe = new PEInfo();
            pe.Machine = machine;
            pe.Architecture = arch;
            pe.ImageBase = imageBase;
            pe.SizeOfHeaders = sizeHeaders;
            pe.Characteristics = characteristics;
            pe.LargeAddressAware = (characteristics & 0x20) != 0;

            int secOff = opt + optionalSize;
            for (int i = 0; i < sectionCount; i++)
            {
                int off = secOff + i * 40;
                if (off + 40 > data.Length) throw new AdapterException("PE section table is truncated.");
                byte[] nameBytes = new byte[8];
                Buffer.BlockCopy(data, off, nameBytes, 0, 8);
                int zero = Array.IndexOf(nameBytes, (byte)0);
                if (zero < 0) zero = 8;
                PESection s = new PESection();
                s.Name = Encoding.ASCII.GetString(nameBytes, 0, zero);
                s.VirtualSize = U32(data, off + 8);
                s.VirtualAddress = U32(data, off + 12);
                s.RawSize = U32(data, off + 16);
                s.RawOffset = U32(data, off + 20);
                s.Characteristics = U32(data, off + 36);
                pe.Sections.Add(s);
            }

            if (arch != "x86")
                throw new AdapterException("KOTOR 1 Windows is a 32-bit x86 game; selected EXE reports " + arch + ".");

            ExeAnalysis result = new ExeAnalysis();
            result.Path = path;
            result.Data = data;
            result.FileSize = data.LongLength;
            result.Sha256 = ComputeSha256(data);
            result.PE = pe;
            return result;
        }

        public static long VaToFileOffset(PEInfo pe, ulong address, long fileSize)
        {
            if (address < pe.ImageBase) return -1;
            ulong rva = address - pe.ImageBase;
            if (rva < pe.SizeOfHeaders && rva < (ulong)fileSize) return (long)rva;
            for (int i = 0; i < pe.Sections.Count; i++)
            {
                PESection s = pe.Sections[i];
                ulong start = s.VirtualAddress;
                ulong span = Math.Max((ulong)s.VirtualSize, (ulong)s.RawSize);
                if (rva >= start && rva < start + span)
                {
                    ulong delta = rva - start;
                    if (delta >= s.RawSize) return -1;
                    ulong off = (ulong)s.RawOffset + delta;
                    return off < (ulong)fileSize ? (long)off : -1;
                }
            }
            return -1;
        }

        public static ulong FileOffsetToVa(PEInfo pe, long fileOffset)
        {
            if (fileOffset < 0) return 0;
            if ((ulong)fileOffset < pe.SizeOfHeaders) return pe.ImageBase + (ulong)fileOffset;
            for (int i = 0; i < pe.Sections.Count; i++)
            {
                PESection s = pe.Sections[i];
                ulong rawStart = s.RawOffset;
                ulong rawEnd = rawStart + s.RawSize;
                if ((ulong)fileOffset >= rawStart && (ulong)fileOffset < rawEnd)
                    return pe.ImageBase + s.VirtualAddress + ((ulong)fileOffset - rawStart);
            }
            return 0;
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private static string BytesHex(byte[] data)
        {
            if (data == null || data.Length == 0) return "(none)";
            return string.Join(" ", data.Select(x => x.ToString("X2")).ToArray());
        }

        private static List<long> FindAll(byte[] data, byte[] needle, int limit)
        {
            List<long> hits = new List<long>();
            if (needle == null || needle.Length == 0 || data.Length < needle.Length) return hits;
            for (int i = 0; i <= data.Length - needle.Length && hits.Count < limit; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (data[i + j] != needle[j]) { ok = false; break; }
                }
                if (ok) hits.Add(i);
            }
            return hits;
        }

        private static string ReadZipText(ZipArchive zip, string name)
        {
            ZipArchiveEntry e = zip.GetEntry(name);
            if (e == null) throw new AdapterException(name + " is missing from the .kpatch archive.");
            using (Stream s = e.Open())
            using (StreamReader r = new StreamReader(s, new UTF8Encoding(false), true))
                return r.ReadToEnd();
        }

        private static string ParseTomlString(string text, string key, string fallback)
        {
            Match m = Regex.Match(text, "(?m)^\\s*" + Regex.Escape(key) + "\\s*=\\s*\"([^\"]*)\"\\s*$");
            return m.Success ? m.Groups[1].Value : fallback;
        }

        private static List<string> ExtractSupportedHashes(string manifest)
        {
            List<string> hashes = new List<string>();
            Match section = Regex.Match(manifest,
                @"(?ms)^\[patch\.supported_versions\]\s*\r?\n(?<body>.*?)(?=^\[[^\r\n]+\]\s*$|\z)");
            if (!section.Success) return hashes;
            MatchCollection ms = Regex.Matches(section.Groups["body"].Value, "\"([0-9A-Fa-f]{64})\"");
            foreach (Match m in ms) hashes.Add(m.Groups[1].Value.ToUpperInvariant());
            return hashes;
        }

        private static List<string> PickHookFiles(ZipArchive zip)
        {
            List<string> candidates = new List<string>();
            foreach (ZipArchiveEntry e in zip.Entries)
                if (e.FullName.EndsWith(".hooks.toml", StringComparison.OrdinalIgnoreCase)) candidates.Add(e.FullName);
            List<string> k1 = candidates.Where(x => System.IO.Path.GetFileName(x).StartsWith("kotor1", StringComparison.OrdinalIgnoreCase)).OrderBy(x => x).ToList();
            if (k1.Count > 0) return k1;
            if (candidates.Count == 1) return candidates;
            return new List<string>();
        }

        private static ulong ParseInteger(string value)
        {
            string s = value.Trim().Replace("_", "");
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ulong.Parse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return ulong.Parse(s, NumberStyles.Integer, CultureInfo.InvariantCulture);
        }

        private static byte[] ParseByteArray(string value)
        {
            MatchCollection nums = Regex.Matches(value, @"0x[0-9A-Fa-f]+|\d+");
            if (nums.Count == 0) return new byte[0];
            byte[] b = new byte[nums.Count];
            for (int i = 0; i < nums.Count; i++)
            {
                ulong n = ParseInteger(nums[i].Value);
                if (n > 255) throw new AdapterException("Byte value is outside 0..255: " + nums[i].Value);
                b[i] = (byte)n;
            }
            return b;
        }

        private static List<Dictionary<string, string>> ParseHookBlocks(string text)
        {
            List<Dictionary<string, string>> list = new List<Dictionary<string, string>>();
            MatchCollection blocks = Regex.Matches(text, @"(?ms)^\s*\[\[hooks\]\]\s*(?<body>.*?)(?=^\s*\[\[hooks\]\]|\z)");
            foreach (Match bm in blocks)
            {
                string body = bm.Groups["body"].Value;
                Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                Match am = Regex.Match(body, @"(?m)^\s*address\s*=\s*([^#\r\n]+)");
                Match tm = Regex.Match(body, "(?m)^\\s*type\\s*=\\s*\"([^\"]+)\"");
                Match om = Regex.Match(body, @"(?ms)^\s*original_bytes\s*=\s*(\[[^\]]*\])");
                Match rm = Regex.Match(body, @"(?ms)^\s*replacement_bytes\s*=\s*(\[[^\]]*\])");
                if (am.Success) d["address"] = am.Groups[1].Value.Trim();
                if (tm.Success) d["type"] = tm.Groups[1].Value.Trim();
                if (om.Success) d["original_bytes"] = om.Groups[1].Value;
                if (rm.Success) d["replacement_bytes"] = rm.Groups[1].Value;
                list.Add(d);
            }
            return list;
        }

        public static PatchAnalysis AnalyzePatch(string patchPath, ExeAnalysis exe)
        {
            PatchAnalysis a = new PatchAnalysis();
            a.Path = patchPath;
            a.PatchId = System.IO.Path.GetFileNameWithoutExtension(patchPath);
            a.PatchName = System.IO.Path.GetFileName(patchPath);

            try
            {
                using (FileStream fs = File.OpenRead(patchPath))
                using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Read))
                {
                    string manifest = ReadZipText(zip, "manifest.toml");
                    a.PatchId = ParseTomlString(manifest, "id", a.PatchId);
                    a.PatchName = ParseTomlString(manifest, "name", a.PatchName);
                    a.ManifestSupported = ExtractSupportedHashes(manifest);
                    a.AlreadySupportsHash = a.ManifestSupported.Contains(exe.Sha256, StringComparer.OrdinalIgnoreCase);

                    a.HookFiles = PickHookFiles(zip);
                    if (a.HookFiles.Count == 0)
                        throw new AdapterException("No KOTOR 1 hooks file was found (expected kotor1*.hooks.toml or one generic *.hooks.toml).");

                    foreach (string hookFile in a.HookFiles)
                    {
                        string text = ReadZipText(zip, hookFile);
                        List<Dictionary<string, string>> blocks = ParseHookBlocks(text);
                        if (blocks.Count == 0) a.Warnings.Add(hookFile + ": contains no [[hooks]] entries.");

                        for (int i = 0; i < blocks.Count; i++)
                        {
                            HookCheck hc = new HookCheck();
                            hc.HookFile = hookFile;
                            hc.Index = i + 1;
                            hc.FileOffset = -1;
                            hc.Status = "malformed";
                            hc.Note = "";
                            try
                            {
                                Dictionary<string, string> d = blocks[i];
                                if (!d.ContainsKey("address") || !d.ContainsKey("type") || !d.ContainsKey("original_bytes"))
                                    throw new AdapterException("Hook is missing address, type, or original_bytes.");
                                hc.Address = ParseInteger(d["address"]);
                                hc.HookType = d["type"].ToLowerInvariant();
                                if (!SupportedHookTypes.Contains(hc.HookType))
                                    throw new AdapterException("Unsupported hook type '" + hc.HookType + "'.");
                                hc.Expected = ParseByteArray(d["original_bytes"]);
                                if (hc.Expected.Length == 0) throw new AdapterException("original_bytes is empty.");
                                byte[] replacement = d.ContainsKey("replacement_bytes") ? ParseByteArray(d["replacement_bytes"]) : null;

                                long off = VaToFileOffset(exe.PE, hc.Address, exe.FileSize);
                                hc.FileOffset = off;
                                if (off < 0 || off + hc.Expected.Length > exe.FileSize)
                                {
                                    hc.Actual = new byte[0];
                                    hc.Status = "unmapped";
                                    hc.Note = "Hook address does not map to bytes in this executable's PE image.";
                                }
                                else
                                {
                                    hc.Actual = new byte[hc.Expected.Length];
                                    Buffer.BlockCopy(exe.Data, (int)off, hc.Actual, 0, hc.Expected.Length);
                                    if (BytesEqual(hc.Actual, hc.Expected))
                                    {
                                        hc.Status = "match";
                                    }
                                    else if (replacement != null && replacement.Length == hc.Expected.Length && BytesEqual(hc.Actual, replacement))
                                    {
                                        hc.Status = "already_replaced";
                                        hc.Note = "The executable already contains this hook's replacement bytes.";
                                    }
                                    else
                                    {
                                        hc.Status = "mismatch";
                                        hc.Note = "Required original bytes differ at the expected address.";
                                        List<long> rawHits = FindAll(exe.Data, hc.Expected, 16);
                                        foreach (long rawHit in rawHits)
                                        {
                                            ulong va = FileOffsetToVa(exe.PE, rawHit);
                                            if (va != 0) hc.SearchHits.Add(va);
                                        }
                                        if (hc.SearchHits.Count == 1)
                                            hc.Note += " The sequence exists once elsewhere at 0x" + hc.SearchHits[0].ToString("X8") + ", but automatic relocation is intentionally refused.";
                                        else if (hc.SearchHits.Count > 1)
                                            hc.Note += " The sequence appears at " + hc.SearchHits.Count.ToString(CultureInfo.InvariantCulture) + " mapped locations, so relocation is ambiguous.";
                                        else
                                            hc.Note += " The required sequence was not found elsewhere in mapped PE sections.";
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                hc.Note = ex.Message;
                            }
                            a.Hooks.Add(hc);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                a.Errors.Add(ex.Message);
            }

            if (a.Hooks.Any(x => x.Status == "malformed")) a.Errors.Add("One or more hooks are malformed.");
            a.Compatible = a.Hooks.Count > 0 && a.Errors.Count == 0 && a.Hooks.All(x => x.Status == "match");
            return a;
        }

        public static List<string> DetectHookOverlaps(List<PatchAnalysis> analyses)
        {
            List<HookSpan> spans = new List<HookSpan>();
            foreach (PatchAnalysis a in analyses)
            {
                if (!a.Compatible) continue;
                foreach (HookCheck h in a.Hooks)
                {
                    if (h.Status != "match") continue;
                    HookSpan s = new HookSpan();
                    s.Start = h.Address;
                    s.End = h.Address + (ulong)h.Expected.Length;
                    s.Patch = a.PatchName;
                    s.Index = h.Index;
                    spans.Add(s);
                }
            }
            spans.Sort(delegate(HookSpan x, HookSpan y) { return x.Start.CompareTo(y.Start); });
            List<string> issues = new List<string>();
            for (int i = 0; i < spans.Count; i++)
            {
                for (int j = i + 1; j < spans.Count; j++)
                {
                    if (spans[j].Start >= spans[i].End) break;
                    if (!string.Equals(spans[i].Patch, spans[j].Patch, StringComparison.OrdinalIgnoreCase) &&
                        Math.Max(spans[i].Start, spans[j].Start) < Math.Min(spans[i].End, spans[j].End))
                    {
                        issues.Add(string.Format(CultureInfo.InvariantCulture,
                            "Hook overlap: {0} hook #{1} [0x{2:X8}-0x{3:X8}] and {4} hook #{5} [0x{6:X8}-0x{7:X8}]",
                            spans[i].Patch, spans[i].Index, spans[i].Start, spans[i].End - 1,
                            spans[j].Patch, spans[j].Index, spans[j].Start, spans[j].End - 1));
                    }
                }
            }
            return issues;
        }

        private sealed class HookSpan
        {
            public ulong Start;
            public ulong End;
            public string Patch;
            public int Index;
        }

        private static string ReplaceSupportedVersions(string text, string exeHash)
        {
            string block = "[patch.supported_versions]\r\n" + CustomVersionKey + " = \"" + exeHash + "\"\r\n";
            Regex r = new Regex(@"(?ms)^\[patch\.supported_versions\][ \t]*\r?\n.*?(?=^\[[^\r\n]+\][ \t]*\r?$|\z)");
            if (r.IsMatch(text)) return r.Replace(text, block, 1);
            return text.TrimEnd() + "\r\n\r\n" + block;
        }

        private static string ReplaceTargetVersions(string text, string exeHash)
        {
            Regex r = new Regex(@"(?ms)(^target_versions\s*=\s*)\[[^\]]*\]");
            string repl = "$1[\r\n    \"" + exeHash + "\"\r\n]";
            if (r.IsMatch(text)) return r.Replace(text, repl, 1);
            Regex meta = new Regex(@"(?m)^\[metadata\][ \t]*$");
            if (meta.IsMatch(text))
                return meta.Replace(text, "[metadata]\r\ntarget_versions = [\r\n    \"" + exeHash + "\"\r\n]", 1);
            throw new AdapterException("Hooks file has no [metadata] table; cannot safely add target_versions.");
        }

        private static void ReplaceZipTextEntry(ZipArchive zip, string name, string content)
        {
            ZipArchiveEntry old = zip.GetEntry(name);
            if (old == null) throw new AdapterException(name + " disappeared while converting patch.");
            old.Delete();
            ZipArchiveEntry replacement = zip.CreateEntry(name, CompressionLevel.Optimal);
            using (Stream s = replacement.Open())
            using (StreamWriter w = new StreamWriter(s, new UTF8Encoding(false)))
                w.Write(content);
        }

        public static string ConvertPatch(PatchAnalysis analysis, ExeAnalysis exe)
        {
            if (!analysis.Compatible) throw new AdapterException("Patch is not safely convertible.");
            string dir = System.IO.Path.GetDirectoryName(analysis.Path);
            string stem = System.IO.Path.GetFileNameWithoutExtension(analysis.Path);
            string suffix = exe.Sha256.Substring(0, 8).ToLowerInvariant();
            string output = System.IO.Path.Combine(dir, stem + "-adapted-" + suffix + ".kpatch");
            int n = 2;
            while (File.Exists(output))
            {
                output = System.IO.Path.Combine(dir, stem + "-adapted-" + suffix + "-" + n.ToString(CultureInfo.InvariantCulture) + ".kpatch");
                n++;
            }

            File.Copy(analysis.Path, output, false);
            try
            {
                using (FileStream fs = new FileStream(output, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Update))
                {
                    string manifest = ReadZipText(zip, "manifest.toml");
                    manifest = ReplaceSupportedVersions(manifest, exe.Sha256);
                    ReplaceZipTextEntry(zip, "manifest.toml", manifest);

                    foreach (string hookFile in analysis.HookFiles)
                    {
                        string hooks = ReadZipText(zip, hookFile);
                        hooks = ReplaceTargetVersions(hooks, exe.Sha256);
                        ReplaceZipTextEntry(zip, hookFile, hooks);
                    }
                }

                PatchAnalysis verify = AnalyzePatch(output, exe);
                if (!verify.Compatible || !verify.AlreadySupportsHash)
                    throw new AdapterException("Converted patch did not pass independent verification.");
                return output;
            }
            catch
            {
                try { if (File.Exists(output)) File.Delete(output); } catch { }
                throw;
            }
        }

        public static string FormatAnalysis(ExeAnalysis exe, List<PatchAnalysis> patches, DbAnalysis db)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("KOTOR KPatch Adapter " + Version);
            sb.AppendLine();
            sb.AppendLine("EXE");
            sb.AppendLine("  Path: " + exe.Path);
            sb.AppendLine("  SHA-256: " + exe.Sha256);
            sb.AppendLine("  Size: " + exe.FileSize.ToString("N0", CultureInfo.InvariantCulture) + " bytes");
            sb.AppendLine("  Architecture: " + exe.PE.Architecture);
            sb.AppendLine("  Image base: 0x" + exe.PE.ImageBase.ToString("X"));
            sb.AppendLine("  Large Address Aware: " + (exe.PE.LargeAddressAware ? "Yes" : "No"));
            sb.AppendLine();
            sb.AppendLine("PATCHES");
            foreach (PatchAnalysis a in patches)
            {
                sb.AppendLine("  " + a.PatchName + " (" + System.IO.Path.GetFileName(a.Path) + ")");
                sb.AppendLine("    Status: " + a.StatusLabel);
                sb.AppendLine("    Hooks matched: " + a.MatchedHooks.ToString(CultureInfo.InvariantCulture) + "/" + a.Hooks.Count.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("    Current EXE already in manifest: " + (a.AlreadySupportsHash ? "Yes" : "No"));
                foreach (string err in a.Errors) sb.AppendLine("    ERROR: " + err);
                foreach (string warn in a.Warnings) sb.AppendLine("    WARNING: " + warn);
                foreach (HookCheck h in a.Hooks)
                {
                    if (h.Status == "match") continue;
                    sb.AppendLine(string.Format(CultureInfo.InvariantCulture,
                        "    Hook #{0} @ 0x{1:X8} [{2}]: {3}", h.Index, h.Address, h.HookType, h.Status.ToUpperInvariant()));
                    if (h.Expected != null) sb.AppendLine("      Expected: " + BytesHex(h.Expected));
                    if (h.Actual != null) sb.AppendLine("      Actual:   " + BytesHex(h.Actual));
                    if (!string.IsNullOrEmpty(h.Note)) sb.AppendLine("      " + h.Note);
                }
                sb.AppendLine();
            }

            List<string> overlaps = DetectHookOverlaps(patches);
            if (overlaps.Count > 0)
            {
                sb.AppendLine("CROSS-PATCH WARNINGS");
                foreach (string s in overlaps) sb.AppendLine("  " + s);
                sb.AppendLine();
            }

            if (db != null)
            {
                sb.AppendLine("PATCH MANAGER DATABASE");
                sb.AppendLine("  Integrity: " + db.Integrity);
                sb.AppendLine("  Valid schema/data: " + (db.Valid ? "Yes" : "No"));
                sb.AppendLine("  Current EXE hash already recognized: " + (db.HasHash ? "Yes" : "No"));
                if (!string.IsNullOrEmpty(db.Error)) sb.AppendLine("  ERROR: " + db.Error);
            }
            return sb.ToString();
        }
    }
}
