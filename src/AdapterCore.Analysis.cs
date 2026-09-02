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
    internal static partial class AdapterCore
    {
        private static HookCheck AnalyzeHook(Dictionary<string, string> d, string hookFile, int index, ExeAnalysis exe)
        {
            HookCheck hc = new HookCheck();
            hc.HookFile = hookFile;
            hc.Index = index;
            hc.FileOffset = -1;
            hc.Status = "malformed";
            hc.Note = "";

            try
            {
                if (!d.ContainsKey("address") || !d.ContainsKey("original_bytes"))
                    throw new AdapterException("Hook is missing address or original_bytes.");

                hc.Address = ParseInteger(d["address"]);
                if (hc.Address > uint.MaxValue)
                    throw new AdapterException("Hook address is outside the 32-bit range used by Kotor Patch Manager.");

                hc.HookType = d.ContainsKey("type") ? d["type"].ToLowerInvariant() : "detour";
                if (!SupportedHookTypes.Contains(hc.HookType))
                    throw new AdapterException("Unsupported hook type '" + hc.HookType + "'.");

                hc.Expected = ParseByteArray(d["original_bytes"]);
                if (hc.Expected.Length == 0) throw new AdapterException("original_bytes is empty.");
                byte[] replacement = d.ContainsKey("replacement_bytes") ? ParseByteArray(d["replacement_bytes"]) : null;

                if (hc.HookType == "detour")
                {
                    if (!d.ContainsKey("function") || string.IsNullOrWhiteSpace(d["function"]))
                        throw new AdapterException("Detour hook is missing function.");
                    if (hc.Expected.Length < 5)
                        throw new AdapterException("Detour original_bytes must contain at least 5 bytes.");
                }
                else if (hc.HookType == "replace")
                {
                    if (replacement == null || replacement.Length == 0)
                        throw new AdapterException("Replace hook is missing replacement_bytes.");
                    if (hc.Expected.Length < 5)
                        throw new AdapterException("Replace original_bytes must contain at least 5 bytes.");
                    if (d.ContainsKey("function") && !string.IsNullOrWhiteSpace(d["function"]))
                        throw new AdapterException("Replace hooks cannot have a function name.");
                    if (d.ContainsKey("has_parameters"))
                        throw new AdapterException("Replace hooks cannot have parameters.");
                }
                else
                {
                    if (replacement == null || replacement.Length == 0)
                        throw new AdapterException(hc.HookType + " hook is missing replacement_bytes.");
                    if (replacement.Length != hc.Expected.Length)
                        throw new AdapterException(hc.HookType + " replacement_bytes length does not match original_bytes length.");
                    if (d.ContainsKey("function") && !string.IsNullOrWhiteSpace(d["function"]))
                        throw new AdapterException(hc.HookType + " hooks cannot have a function name.");
                    if (d.ContainsKey("has_parameters"))
                        throw new AdapterException(hc.HookType + " hooks cannot have parameters.");
                }

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

            return hc;
        }

        private static HookFileInfo AnalyzeHookFile(string name, string text, ExeAnalysis exe)
        {
            HookFileInfo info = new HookFileInfo();
            info.Name = name;
            TargetVersionInfo targetInfo = ExtractTargetVersions(text);
            info.TargetVersions.AddRange(targetInfo.Hashes);

            List<Dictionary<string, string>> blocks = ParseHookBlocks(text);
            for (int i = 0; i < blocks.Count; i++)
                info.Hooks.Add(AnalyzeHook(blocks[i], name, i + 1, exe));

            string behavior = Regex.Replace(text,
                @"(?ms)^[ \t]*\[metadata\][ \t]*(?:\#[^\r\n]*)?\r?\n.*?(?=^[ \t]*\[[^\r\n]+\][ \t]*(?:\#[^\r\n]*)?\r?$|\z)", "");
            behavior = StripTomlComments(behavior).Replace("\r\n", "\n");
            behavior = Regex.Replace(behavior, @"\s+", "");
            info.BehaviorSignature = ComputeSha256(Encoding.UTF8.GetBytes(behavior));
            return info;
        }

        private static string FileSetKey(IEnumerable<HookFileInfo> files)
        {
            return string.Join("\n", files.Select(x => x.Name).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray());
        }

        private static string BehaviorKey(IEnumerable<HookFileInfo> files)
        {
            return string.Join("\n", files.Select(x => x.BehaviorSignature).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray());
        }

        private static bool BundleAppliesToHash(HookBundle bundle, string hash)
        {
            return bundle.Files.All(x => x.TargetVersions.Count == 0 || x.TargetVersions.Contains(hash, StringComparer.OrdinalIgnoreCase));
        }

        private static HookBundle MakeBundle(List<HookFileInfo> files)
        {
            HookBundle bundle = new HookBundle();
            bundle.Files.AddRange(files.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase));
            foreach (HookFileInfo file in bundle.Files) bundle.Hooks.AddRange(file.Hooks);
            bundle.BehaviorSignature = BehaviorKey(bundle.Files);
            bundle.MatchedHooks = bundle.Hooks.Count(x => x.Status == "match");
            bundle.Compatible = bundle.Hooks.Count > 0 && bundle.Hooks.All(x => x.Status == "match");
            return bundle;
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
                    bool manifestHasHash = a.ManifestSupported.Contains(exe.Sha256, StringComparer.OrdinalIgnoreCase);

                    List<ZipArchiveEntry> hookEntries = zip.Entries
                        .Where(x => !string.IsNullOrEmpty(x.Name) && IsHooksFile(x.FullName))
                        .OrderBy(x => x.FullName, StringComparer.OrdinalIgnoreCase)
                        .ToList();
                    if (hookEntries.Count == 0)
                        throw new AdapterException("No hooks.toml file was found. Kotor Patch Manager 0.6.3 accepts hooks.toml and names ending in hooks.toml.");

                    List<HookFileInfo> infos = new List<HookFileInfo>();
                    foreach (ZipArchiveEntry entry in hookEntries)
                        infos.Add(AnalyzeHookFile(entry.FullName, ReadZipText(zip, entry.FullName), exe));

                    List<string> candidateHashes = new List<string>();
                    foreach (string hash in a.ManifestSupported)
                        if (!candidateHashes.Contains(hash, StringComparer.OrdinalIgnoreCase)) candidateHashes.Add(hash);
                    foreach (string hash in infos.SelectMany(x => x.TargetVersions))
                        if (Regex.IsMatch(hash, @"^[0-9A-F]{64}$") &&
                            !candidateHashes.Contains(hash, StringComparer.OrdinalIgnoreCase)) candidateHashes.Add(hash);

                    Dictionary<string, HookBundle> bundlesByFiles = new Dictionary<string, HookBundle>(StringComparer.OrdinalIgnoreCase);
                    if (candidateHashes.Count == 0)
                    {
                        List<HookFileInfo> genericFiles = infos.Where(x => x.TargetVersions.Count == 0).ToList();
                        HookBundle genericBundle = MakeBundle(genericFiles);
                        bundlesByFiles[FileSetKey(genericFiles)] = genericBundle;
                    }
                    else
                    {
                        foreach (string hash in candidateHashes)
                        {
                            List<HookFileInfo> files = infos
                                .Where(x => x.TargetVersions.Count == 0 || x.TargetVersions.Contains(hash, StringComparer.OrdinalIgnoreCase))
                                .ToList();
                            string key = FileSetKey(files);
                            HookBundle bundle;
                            if (!bundlesByFiles.TryGetValue(key, out bundle))
                            {
                                bundle = MakeBundle(files);
                                bundlesByFiles[key] = bundle;
                            }
                            bundle.SourceHashes.Add(hash);
                        }
                    }

                    List<HookBundle> bundles = bundlesByFiles.Values.ToList();
                    HookBundle currentBundle = bundles.FirstOrDefault(x => x.SourceHashes.Contains(exe.Sha256, StringComparer.OrdinalIgnoreCase));
                    HookBundle chosen = null;

                    if (manifestHasHash && currentBundle != null && currentBundle.Compatible)
                    {
                        chosen = currentBundle;
                        a.AlreadySupportsHash = true;
                    }
                    else
                    {
                        List<HookBundle> compatible = bundles.Where(x => x.Compatible).ToList();
                        List<IGrouping<string, HookBundle>> behaviorGroups = compatible
                            .GroupBy(x => x.BehaviorSignature, StringComparer.OrdinalIgnoreCase)
                            .ToList();

                        if (behaviorGroups.Count == 1)
                        {
                            chosen = behaviorGroups[0]
                                .OrderByDescending(x => x.SourceHashes.Count(h => a.ManifestSupported.Contains(h, StringComparer.OrdinalIgnoreCase)))
                                .ThenBy(x => FileSetKey(x.Files), StringComparer.OrdinalIgnoreCase)
                                .First();
                            if (compatible.Count > 1)
                                a.Warnings.Add("Multiple source-version hook bundles matched, but they contain equivalent hook behavior. The adapter selected one deterministic bundle.");
                        }
                        else if (behaviorGroups.Count > 1)
                        {
                            a.Errors.Add("More than one distinct version-specific hook bundle matches this EXE. Automatic conversion is ambiguous and has been blocked.");
                            chosen = compatible
                                .OrderByDescending(x => x.MatchedHooks)
                                .ThenBy(x => FileSetKey(x.Files), StringComparer.OrdinalIgnoreCase)
                                .First();
                        }
                        else
                        {
                            a.Errors.Add("No complete Kotor Patch Manager 0.6.3 hook bundle matches this EXE.");
                            chosen = bundles
                                .OrderByDescending(x => x.MatchedHooks)
                                .ThenBy(x => x.Hooks.Count - x.MatchedHooks)
                                .ThenBy(x => FileSetKey(x.Files), StringComparer.OrdinalIgnoreCase)
                                .FirstOrDefault();
                        }
                    }

                    if (chosen == null)
                        throw new AdapterException("No applicable hook bundle could be selected from the patch archive.");

                    a.HookFiles.AddRange(chosen.Files.Select(x => x.Name));
                    a.Hooks.AddRange(chosen.Hooks);

                    foreach (HookFileInfo file in chosen.Files)
                        if (file.Hooks.Count == 0) a.Warnings.Add(file.Name + ": contains no [[hooks]] entries.");

                    int ignored = infos.Count(x => !chosen.Files.Contains(x));
                    if (ignored > 0)
                        a.Warnings.Add(ignored.ToString(CultureInfo.InvariantCulture) + " alternate version-specific hooks file(s) were left unselected.");
                    if (chosen.Files.Any(x => x.TargetVersions.Count == 0))
                        a.Warnings.Add("Generic hooks.toml content applies to every manifest-supported version and will remain generic during conversion.");

                    if (manifestHasHash && !a.AlreadySupportsHash)
                    {
                        if (BundleAppliesToHash(chosen, exe.Sha256) && chosen.Compatible)
                            a.AlreadySupportsHash = true;
                        else
                            a.Warnings.Add("The manifest lists this EXE hash, but the selected version-specific hook metadata does not yet target it.");
                    }
                }
            }
            catch (Exception ex)
            {
                a.Errors.Add(ex.Message);
            }

            if (a.Hooks.Any(x => x.Status == "malformed") && !a.Errors.Contains("One or more hooks are malformed."))
                a.Errors.Add("One or more hooks are malformed.");
            a.Compatible = a.Hooks.Count > 0 && a.Errors.Count == 0 && a.Hooks.All(x => x.Status == "match");
            return a;
        }
    }
}
