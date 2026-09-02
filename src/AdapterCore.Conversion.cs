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

        private sealed class TargetVersionInfo
        {
            public List<string> Hashes = new List<string>();
        }

        private sealed class HookFileInfo
        {
            public string Name;
            public string BehaviorSignature;
            public List<string> TargetVersions = new List<string>();
            public List<HookCheck> Hooks = new List<HookCheck>();
        }

        private sealed class HookBundle
        {
            public List<HookFileInfo> Files = new List<HookFileInfo>();
            public List<HookCheck> Hooks = new List<HookCheck>();
            public List<string> SourceHashes = new List<string>();
            public string BehaviorSignature;
            public int MatchedHooks;
            public bool Compatible;
        }

        private static string PreferredNewLine(string text)
        {
            return text.Contains("\r\n") ? "\r\n" : "\n";
        }

        private static string AddSupportedVersion(string text, string exeHash)
        {
            if (ExtractSupportedHashes(text).Contains(exeHash, StringComparer.OrdinalIgnoreCase)) return text;

            string nl = PreferredNewLine(text);
            string keyBase = CustomVersionKeyPrefix + exeHash.Substring(0, 12).ToLowerInvariant();
            string key = keyBase;
            int suffix = 2;
            while (Regex.IsMatch(text, @"(?m)^[ \t]*" + Regex.Escape(key) + @"[ \t]*="))
            {
                key = keyBase + "_" + suffix.ToString(CultureInfo.InvariantCulture);
                suffix++;
            }
            string line = key + " = \"" + exeHash + "\"" + nl;
            Match section = FindTomlTable(text, "patch.supported_versions");
            if (section.Success)
            {
                Group body = section.Groups["body"];
                string prefix = body.Length > 0 && !body.Value.EndsWith("\n", StringComparison.Ordinal) ? nl : "";
                return text.Insert(body.Index + body.Length, prefix + line);
            }

            return text.TrimEnd() + nl + nl + "[patch.supported_versions]" + nl + line;
        }

        private static string AddTargetVersion(string text, string exeHash)
        {
            TargetVersionInfo info = ExtractTargetVersions(text);
            if (info.Hashes.Count == 0 || info.Hashes.Contains(exeHash, StringComparer.OrdinalIgnoreCase)) return text;

            Match metadata = FindTomlTable(text, "metadata");
            if (!metadata.Success) return text;
            Match target = Regex.Match(metadata.Groups["body"].Value,
                @"(?ms)^(?<indent>[ \t]*)target_versions(?<spacing>[ \t]*=[ \t]*)\[(?<values>.*?)\]");
            if (!target.Success) return text;

            List<string> values = new List<string>(info.Hashes);
            values.Add(exeHash.ToUpperInvariant());
            string nl = PreferredNewLine(text);
            string indent = target.Groups["indent"].Value;
            string spacing = target.Groups["spacing"].Value;
            string originalValues = target.Groups["values"].Value;
            string replacement;

            if (originalValues.IndexOf('\n') >= 0 || originalValues.IndexOf('\r') >= 0)
            {
                Match valueIndentMatch = Regex.Match(originalValues, "(?m)^([ \\t]*)\"");
                string valueIndent = valueIndentMatch.Success ? valueIndentMatch.Groups[1].Value : indent + "    ";
                replacement = indent + "target_versions" + spacing + "[" + nl +
                    string.Join("," + nl, values.Select(x => valueIndent + "\"" + x + "\"").ToArray()) + nl +
                    indent + "]";
            }
            else
            {
                replacement = indent + "target_versions" + spacing + "[" +
                    string.Join(", ", values.Select(x => "\"" + x + "\"").ToArray()) + "]";
            }

            int absoluteStart = metadata.Groups["body"].Index + target.Index;
            return text.Substring(0, absoluteStart) + replacement +
                text.Substring(absoluteStart + target.Length);
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
                    manifest = AddSupportedVersion(manifest, exe.Sha256);
                    ReplaceZipTextEntry(zip, "manifest.toml", manifest);

                    foreach (string hookFile in analysis.HookFiles)
                    {
                        string hooks = ReadZipText(zip, hookFile);
                        string updated = AddTargetVersion(hooks, exe.Sha256);
                        if (!string.Equals(hooks, updated, StringComparison.Ordinal))
                            ReplaceZipTextEntry(zip, hookFile, updated);
                    }
                }

                PatchAnalysis verify = AnalyzePatch(output, exe);
                if (!verify.Compatible || !verify.AlreadySupportsHash)
                    throw new AdapterException("Converted patch did not pass independent Kotor Patch Manager 0.6.3 verification.");
                return output;
            }
            catch
            {
                try { if (File.Exists(output)) File.Delete(output); } catch { }
                throw;
            }
        }
    }
}
