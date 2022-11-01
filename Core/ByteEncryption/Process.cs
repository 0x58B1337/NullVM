using Core.Protection;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
//using ConversionBack;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.IO.Compression;

namespace Core.ByteEncryption
{
    class Process
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibrary(string dllToLoad);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, EntryPoint = "GetProcAddress", ExactSpelling = true)]
        private static extern IntPtr e(IntPtr intptr, string str);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, EntryPoint = "GetModuleHandle")]
        private static extern IntPtr ab(string str);
        public delegate void abc(byte[] bytes, int len, byte[] key, int keylen);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibraryEx(string dllToLoad, IntPtr hFile, uint flags);

        public static byte[] tester(MethodDef methodDef, ModuleDefMD updated)
        {
            dnlib.IO.IImageStream streamFull = updated.MetaData.PEImage.CreateFullStream();
            var upated = (updated.ResolveToken(methodDef.MDToken.ToInt32()) as MethodDef);
            var offset = updated.MetaData.PEImage.ToFileOffset(upated.RVA);
            streamFull.Position = (long)offset;
            byte b = streamFull.ReadByte();

            ushort flags;
            byte headerSize;
            ushort maxStack;
            uint codeSize = 0;

            switch (b & 7)
            {
                case 2:
                case 6:
                    flags = 2;
                    maxStack = 8;
                    codeSize = (uint)(b >> 2);
                    headerSize = 1;
                    break;

                case 3:
                    flags = (ushort)((streamFull.ReadByte() << 8) | b);
                    headerSize = (byte)(flags >> 12);
                    maxStack = streamFull.ReadUInt16();
                    codeSize = streamFull.ReadUInt32();
                    break;
            }
            if (codeSize != 0)
            {
                byte[] il_byte = new byte[codeSize];
                streamFull.Position = (long)offset + upated.Body.HeaderSize;
                streamFull.Read(il_byte, 0, il_byte.Length);
                return il_byte;
            }
            return null;
        }
        [DllImport("NativePRo.dll")]
        public static extern void a(byte[] bytes, int len, byte[] key, int keylen);
        static byte[] Compress(byte[] data)
        {
            using (var compressedStream = new MemoryStream())
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Compress))
            {
                zipStream.Write(data, 0, data.Length);
                zipStream.Close();
                return compressedStream.ToArray();
            }
        }
        public unsafe static void processConvertedMethods(List<MethodData> allMethodDatas)
        {
            int pos =0;
            Stream tester = new MemoryStream();
            ModuleWriterOptions modopts = new ModuleWriterOptions(Protector.moduleDefMD);
            modopts.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;
            modopts.Logger = DummyLogger.NoThrowInstance;
            Protector.moduleDefMD.Write(tester, modopts);
            ModuleDefMD updated = ModuleDefMD.Load(tester);

            foreach (MethodData methodData in allMethodDatas)
            {
                var decryptedBytes = methodData.DecryptedBytes;
                var method = methodData.Method;
                var md5 = MD5.Create();
                byte[] methodBytes = Process.tester(method, updated) ;

                var nameHash = md5.ComputeHash(Encoding.ASCII.GetBytes(method.Name + methodData.ID));
            


                var enc = ByteEncryption.Encrypt(nameHash, decryptedBytes);
           

               
                enc = aMethod2(enc, enc.Length, methodBytes, methodBytes.Length);
               
            
                methodData.EncryptedBytes = enc;

                methodData.Encrypted = true;
                methodData.size = methodData.EncryptedBytes.Length;
                methodData.position = pos;
                pos += methodData.EncryptedBytes.Length;
      




            }
        }
     
        [Obfuscation(Feature = "virtualization", Exclude = false)]
        private static byte[] b(byte[] toEncrypt, int len)
        {
            string key = "NULL&%+^!/="; //Any chars will work, in an array of any size
            byte[] output = toEncrypt;

            for (int i = 0; i < len; i++)
            {
             
                output[i] = (byte)(toEncrypt[i] ^ key[i % (key.Length)]);
            }

            return output;
        }
        [Obfuscation(Feature = "virtualization", Exclude = false)]
       
        private static byte[] aMethod2(byte[] data, int datalen, byte[] key, int keylen)
        {
           
            return b(data, datalen);

        }

        public static byte[] aMethod(byte[] data, int datalen, byte[] key, int keylen)
        {
         
            return Bmethod(data, data.Length);
        }
        
        public static byte[] Bmethod(byte[] toEncrypt, int len)
        {
            char[] key = { 'N', 'U', 'L', 'L', '&', '%', '+', '^', '!', '/', '=' };
            byte[] output = toEncrypt;
            for (int i = 0; i < len; i++)
                output[i] = (byte)(toEncrypt[i] ^ key[i % (11 / sizeof(char))]);
            return output;

        }
    }
}
