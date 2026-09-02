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
                sb.AppendLine("    Hook files selected: " + (a.HookFiles.Count == 0 ? "(none)" : string.Join(", ", a.HookFiles.ToArray())));
                sb.AppendLine("    Hooks matched: " + a.MatchedHooks.ToString(CultureInfo.InvariantCulture) + "/" + a.Hooks.Count.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("    Current EXE fully targeted by patch: " + (a.AlreadySupportsHash ? "Yes" : "No"));
                foreach (string err in a.Errors) sb.AppendLine("    ERROR: " + err);
                foreach (string warn in a.Warnings) sb.AppendLine("    WARNING: " + warn);
                foreach (HookCheck h in a.Hooks)
                {
                    if (h.Status == "match") continue;
                    sb.AppendLine(string.Format(CultureInfo.InvariantCulture,
                        "    {0} hook #{1} @ 0x{2:X8} [{3}]: {4}", h.HookFile, h.Index, h.Address, h.HookType, h.Status.ToUpperInvariant()));
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
