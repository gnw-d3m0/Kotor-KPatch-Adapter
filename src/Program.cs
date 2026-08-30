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
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    internal sealed class AdapterException : Exception
    {
        public AdapterException(string message) : base(message) { }
        public AdapterException(string message, Exception inner) : base(message, inner) { }
    }

    internal sealed class PESection
    {
        public string Name;
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint RawOffset;
        public uint RawSize;
        public uint Characteristics;
    }

    internal sealed class PEInfo
    {
        public ushort Machine;
        public string Architecture;
        public ulong ImageBase;
        public uint SizeOfHeaders;
        public ushort Characteristics;
        public bool LargeAddressAware;
        public List<PESection> Sections = new List<PESection>();
    }

    internal sealed class ExeAnalysis
    {
        public string Path;
        public string Sha256;
        public long FileSize;
        public byte[] Data;
        public PEInfo PE;
    }

    internal sealed class HookCheck
    {
        public string HookFile;
        public int Index;
        public ulong Address;
        public string HookType;
        public byte[] Expected;
        public byte[] Actual;
        public long FileOffset;
        public string Status;
        public string Note;
        public List<ulong> SearchHits = new List<ulong>();
    }

    internal sealed class PatchAnalysis
    {
        public string Path;
        public string PatchId;
        public string PatchName;
        public List<string> ManifestSupported = new List<string>();
        public List<string> HookFiles = new List<string>();
        public List<HookCheck> Hooks = new List<HookCheck>();
        public List<string> Errors = new List<string>();
        public List<string> Warnings = new List<string>();
        public bool Compatible;
        public bool AlreadySupportsHash;

        public int MatchedHooks
        {
            get { return Hooks.Count(x => x.Status == "match"); }
        }

        public string StatusLabel
        {
            get
            {
                if (Errors.Count > 0) return "ERROR";
                if (Compatible)
                    return AlreadySupportsHash ? "COMPATIBLE (already supports EXE)" : "COMPATIBLE - can convert";
                if (Hooks.Any(x => x.Status == "already_replaced")) return "REVIEW - hook already changed";
                return "INCOMPATIBLE";
            }
        }
    }

    internal sealed class DbAnalysis
    {
        public bool Valid;
        public string Integrity;
        public bool HasHash;
        public string Error;
        public List<string> Versions = new List<string>();
    }

    internal sealed class PatchListItem
    {
        public string Path;
        public override string ToString() { return System.IO.Path.GetFileName(Path); }
    }
}
