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
        private static Match FindTomlTable(string text, string tableName)
        {
            return Regex.Match(text,
                @"(?ms)^[ \t]*\[" + Regex.Escape(tableName) + @"\][ \t]*(?:\#[^\r\n]*)?\r?\n(?<body>.*?)(?=^[ \t]*\[[^\r\n]+\][ \t]*(?:\#[^\r\n]*)?\r?$|\z)");
        }

        private static List<string> ExtractSupportedHashes(string manifest)
        {
            List<string> hashes = new List<string>();
            Match section = FindTomlTable(manifest, "patch.supported_versions");
            if (!section.Success) return hashes;
            MatchCollection ms = Regex.Matches(section.Groups["body"].Value, "\"([0-9A-Fa-f]{64})\"");
            foreach (Match m in ms)
            {
                string hash = m.Groups[1].Value.ToUpperInvariant();
                if (!hashes.Contains(hash, StringComparer.OrdinalIgnoreCase)) hashes.Add(hash);
            }
            return hashes;
        }

        private static TargetVersionInfo ExtractTargetVersions(string text)
        {
            TargetVersionInfo result = new TargetVersionInfo();
            Match metadata = FindTomlTable(text, "metadata");
            if (!metadata.Success) return result;

            Match target = Regex.Match(metadata.Groups["body"].Value,
                @"(?ms)^(?<prefix>[ \t]*target_versions[ \t]*=[ \t]*)\[(?<values>.*?)\]");
            if (!target.Success) return result;

            MatchCollection values = Regex.Matches(target.Groups["values"].Value, "\"([^\"]+)\"");
            foreach (Match value in values)
            {
                string hash = value.Groups[1].Value.Trim().ToUpperInvariant();
                if (hash.Length > 0 && !result.Hashes.Contains(hash, StringComparer.OrdinalIgnoreCase)) result.Hashes.Add(hash);
            }
            return result;
        }

        private static string ArchiveFileName(string path)
        {
            string normalized = path.Replace('\\', '/');
            int slash = normalized.LastIndexOf('/');
            return slash >= 0 ? normalized.Substring(slash + 1) : normalized;
        }

        private static bool IsHooksFile(string path)
        {
            string name = ArchiveFileName(path);
            return name.EndsWith("hooks.toml", StringComparison.OrdinalIgnoreCase);
        }

        private static ulong ParseInteger(string value)
        {
            string s = value.Trim().Replace("_", "");
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ulong.Parse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return ulong.Parse(s, NumberStyles.Integer, CultureInfo.InvariantCulture);
        }

        private static string StripTomlComments(string value)
        {
            StringBuilder output = new StringBuilder(value.Length);
            bool inString = false;
            bool escaped = false;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (inString)
                {
                    output.Append(c);
                    if (escaped) escaped = false;
                    else if (c == '\\') escaped = true;
                    else if (c == '"') inString = false;
                    continue;
                }

                if (c == '"')
                {
                    inString = true;
                    output.Append(c);
                    continue;
                }

                if (c == '#')
                {
                    while (i < value.Length && value[i] != '\r' && value[i] != '\n') i++;
                    if (i < value.Length) output.Append(value[i]);
                    continue;
                }

                output.Append(c);
            }
            return output.ToString();
        }

        private static byte[] ParseByteArray(string value)
        {
            string clean = StripTomlComments(value);
            MatchCollection nums = Regex.Matches(clean, @"0x[0-9A-Fa-f]+|\d+");
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
            MatchCollection blocks = Regex.Matches(text,
                @"(?ms)^[ \t]*\[\[hooks\]\][ \t]*(?:\#[^\r\n]*)?\r?\n?(?<body>.*?)(?=^[ \t]*\[\[hooks\]\][ \t]*(?:\#[^\r\n]*)?\r?$|\z)");
            foreach (Match bm in blocks)
            {
                string body = bm.Groups["body"].Value;
                Match nested = Regex.Match(body, @"(?m)^[ \t]*\[\[hooks\.");
                bool hasParameters = nested.Success;
                if (nested.Success) body = body.Substring(0, nested.Index);

                Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (hasParameters) d["has_parameters"] = "true";
                Match am = Regex.Match(body, @"(?m)^[ \t]*address[ \t]*=[ \t]*([^#\r\n]+)");
                Match tm = Regex.Match(body, "(?m)^[ \\t]*type[ \\t]*=[ \\t]*\"([^\"]+)\"");
                Match fm = Regex.Match(body, "(?m)^[ \\t]*function[ \\t]*=[ \\t]*\"([^\"]+)\"");
                Match om = Regex.Match(body, @"(?ms)^[ \t]*original_bytes[ \t]*=[ \t]*(\[[^\]]*\])");
                Match rm = Regex.Match(body, @"(?ms)^[ \t]*replacement_bytes[ \t]*=[ \t]*(\[[^\]]*\])");
                if (am.Success) d["address"] = am.Groups[1].Value.Trim();
                if (tm.Success) d["type"] = tm.Groups[1].Value.Trim();
                if (fm.Success) d["function"] = fm.Groups[1].Value.Trim();
                if (om.Success) d["original_bytes"] = om.Groups[1].Value;
                if (rm.Success) d["replacement_bytes"] = rm.Groups[1].Value;
                list.Add(d);
            }
            return list;
        }
    }
}
