// Parser de PE (Portable Executable) minimo y de solo lectura.
// Lee bytes de archivo directamente (sin mapear el binario en memoria ni ejecutarlo).
// Cubre: cabecera DOS/NT, secciones, tabla de importacion (DLL + funciones u ordinales).
// No valida firmas Authenticode (eso lo hace Get-AuthenticodeSignature, solo en Windows).
using System;
using System.Collections.Generic;
using System.Text;

namespace DriverTriage
{
    public sealed class PESection
    {
        public string Name;
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint Characteristics;
        public bool IsExecutable { get { return (Characteristics & 0x20000000) != 0; } }
        public bool IsWritable   { get { return (Characteristics & 0x80000000) != 0; } }
    }

    public sealed class PEImportFunction
    {
        public string Name;       // null si es importacion por ordinal
        public ushort Hint;
        public ushort Ordinal;    // valido solo si Name es null
        public bool IsOrdinal { get { return Name == null; } }
    }

    public sealed class PEImportModule
    {
        public string DllName;
        public List<PEImportFunction> Functions = new List<PEImportFunction>();
    }

    public sealed class PEParseResult
    {
        public bool Success;
        public string Error;

        public ushort Machine;
        public bool Is64Bit;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint Characteristics;
        public uint TimeDateStamp;
        public uint SizeOfImage;
        public uint AddressOfEntryPoint;
        public bool HasSecurityDirectory;   // data directory 4 (certificado embebido); no se verifica, solo se marca

        public List<PESection> Sections = new List<PESection>();
        public List<PEImportModule> Imports = new List<PEImportModule>();
        public bool ImportParseTruncated;   // true si se alcanzo un limite de seguridad durante el parseo

        public bool IsDriverLike { get { return Subsystem == 1; } }   // IMAGE_SUBSYSTEM_NATIVE
    }

    public static class PEParser
    {
        private const int MaxDescriptors = 4096;
        private const int MaxFunctionsPerModule = 8192;
        private const int MaxNameLength = 512;

        public static PEParseResult Parse(byte[] data)
        {
            var r = new PEParseResult();
            try
            {
                if (data == null || data.Length < 0x40) { r.Error = "archivo demasiado pequeno"; return r; }
                if (data[0] != 0x4D || data[1] != 0x5A) { r.Error = "falta firma MZ"; return r; }

                uint e_lfanew = ReadU32(data, 0x3C);
                if (e_lfanew + 24 + 2 > (uint)data.Length) { r.Error = "e_lfanew fuera de rango"; return r; }
                if (!(data[e_lfanew] == (byte)'P' && data[e_lfanew + 1] == (byte)'E' && data[e_lfanew + 2] == 0 && data[e_lfanew + 3] == 0))
                { r.Error = "falta firma PE"; return r; }

                uint coffOff = e_lfanew + 4;
                r.Machine = ReadU16(data, coffOff);
                ushort numSections = ReadU16(data, coffOff + 2);
                r.TimeDateStamp = ReadU32(data, coffOff + 4);
                ushort sizeOfOptHdr = ReadU16(data, coffOff + 16);
                r.Characteristics = ReadU16(data, coffOff + 18);

                uint optOff = coffOff + 20;
                if (optOff + 2 > data.Length) { r.Error = "optional header fuera de rango"; return r; }
                ushort magic = ReadU16(data, optOff);
                r.Is64Bit = magic == 0x20B;
                if (!r.Is64Bit && magic != 0x10B) { r.Error = "magic de optional header desconocido"; return r; }

                uint ddStartOff;      // offset de DataDirectory dentro del optional header
                if (r.Is64Bit)
                {
                    r.AddressOfEntryPoint = ReadU32(data, optOff + 16);
                    r.SizeOfImage = ReadU32(data, optOff + 56);
                    r.Subsystem = ReadU16(data, optOff + 68);
                    r.DllCharacteristics = ReadU16(data, optOff + 70);
                    ddStartOff = optOff + 112;
                }
                else
                {
                    r.AddressOfEntryPoint = ReadU32(data, optOff + 16);
                    r.SizeOfImage = ReadU32(data, optOff + 56);
                    r.Subsystem = ReadU16(data, optOff + 68);
                    r.DllCharacteristics = ReadU16(data, optOff + 70);
                    ddStartOff = optOff + 96;
                }

                uint importDirRva = 0, importDirSize = 0;
                uint numDD = ReadU32(data, (r.Is64Bit ? optOff + 108 : optOff + 92));
                if (numDD > 2) { importDirRva = ReadU32(data, ddStartOff + 1 * 8); importDirSize = ReadU32(data, ddStartOff + 1 * 8 + 4); }
                if (numDD > 4) { r.HasSecurityDirectory = ReadU32(data, ddStartOff + 4 * 8 + 4) > 0; }

                uint secTableOff = optOff + sizeOfOptHdr;
                for (int i = 0; i < numSections; i++)
                {
                    uint so = secTableOff + (uint)(i * 40);
                    if (so + 40 > data.Length) break;
                    var s = new PESection
                    {
                        Name = ReadFixedAscii(data, so, 8),
                        VirtualSize = ReadU32(data, so + 8),
                        VirtualAddress = ReadU32(data, so + 12),
                        SizeOfRawData = ReadU32(data, so + 16),
                        PointerToRawData = ReadU32(data, so + 20),
                        Characteristics = ReadU32(data, so + 36)
                    };
                    r.Sections.Add(s);
                }

                if (importDirRva != 0)
                {
                    ParseImports(data, r, importDirRva);
                }

                r.Success = true;
                return r;
            }
            catch (Exception ex)
            {
                r.Error = "excepcion de parseo: " + ex.Message;
                return r;
            }
        }

        private static void ParseImports(byte[] data, PEParseResult r, uint importDirRva)
        {
            long descOffL = RvaToOffset(r, importDirRva);
            if (descOffL < 0) return;
            uint descOff = (uint)descOffL;

            for (int i = 0; i < MaxDescriptors; i++)
            {
                uint baseOff = descOff + (uint)(i * 20);
                if (baseOff + 20 > data.Length) { r.ImportParseTruncated = true; break; }
                uint origFirstThunk = ReadU32(data, baseOff);
                uint nameRva = ReadU32(data, baseOff + 12);
                uint firstThunk = ReadU32(data, baseOff + 16);
                if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

                var mod = new PEImportModule();
                long nameOffL = RvaToOffset(r, nameRva);
                mod.DllName = nameOffL >= 0 ? ReadAsciiZ(data, (uint)nameOffL, MaxNameLength) : "(nombre ilegible)";

                uint thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
                long thunkOffL = RvaToOffset(r, thunkRva);
                if (thunkOffL >= 0)
                {
                    uint thunkOff = (uint)thunkOffL;
                    int entrySize = r.Is64Bit ? 8 : 4;
                    for (int j = 0; j < MaxFunctionsPerModule; j++)
                    {
                        uint eo = thunkOff + (uint)(j * entrySize);
                        if (eo + entrySize > data.Length) { r.ImportParseTruncated = true; break; }
                        ulong entry = entrySize == 8 ? ReadU64(data, eo) : ReadU32(data, eo);
                        if (entry == 0) break;

                        var fn = new PEImportFunction();
                        bool ordinalFlag = entrySize == 8 ? (entry & 0x8000000000000000UL) != 0 : (entry & 0x80000000UL) != 0;
                        if (ordinalFlag)
                        {
                            fn.Ordinal = (ushort)(entry & 0xFFFF);
                        }
                        else
                        {
                            long hnOffL = RvaToOffset(r, (uint)(entry & 0xFFFFFFFF));
                            if (hnOffL >= 0)
                            {
                                uint hnOff = (uint)hnOffL;
                                fn.Hint = ReadU16(data, hnOff);
                                fn.Name = ReadAsciiZ(data, hnOff + 2, MaxNameLength);
                            }
                        }
                        mod.Functions.Add(fn);
                    }
                }
                r.Imports.Add(mod);
            }
        }

        private static long RvaToOffset(PEParseResult r, uint rva)
        {
            foreach (var s in r.Sections)
            {
                uint size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                    return s.PointerToRawData + (rva - s.VirtualAddress);
            }
            return -1;
        }

        private static ushort ReadU16(byte[] d, uint o) { return (ushort)(d[o] | (d[o + 1] << 8)); }
        private static uint ReadU32(byte[] d, uint o) { return (uint)(d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)); }
        private static ulong ReadU64(byte[] d, uint o)
        {
            ulong lo = ReadU32(d, o);
            ulong hi = ReadU32(d, o + 4);
            return lo | (hi << 32);
        }
        private static string ReadFixedAscii(byte[] d, uint o, int len)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < len; i++) { byte b = d[o + i]; if (b == 0) break; sb.Append((char)b); }
            return sb.ToString();
        }
        private static string ReadAsciiZ(byte[] d, uint o, int maxLen)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++)
            {
                if (o + i >= d.Length) break;
                byte b = d[o + i];
                if (b == 0) break;
                sb.Append((char)b);
            }
            return sb.ToString();
        }
    }
}
