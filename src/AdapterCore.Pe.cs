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
        public const string Version = "0.2.0";
        public const string ToolMarker = "KPatch Adapter:";
        public const string CustomVersionKeyPrefix = "kotor1_custom_103_";

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
    }
}
