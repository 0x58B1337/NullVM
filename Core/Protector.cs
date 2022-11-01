using System;
using System.Linq;
using System.Reflection;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using IL_Emulator_Dynamic;
using Core.Properties;
using VMExample.Instructions;
using System.Text;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using MethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using dnlib.DotNet.Emit;

namespace Core
{
    public class Protector
    {
        public static string path2;

        public static ModuleDefMD moduleDefMD { get; private set; }
        public static string name { get; private set; }

        public static void RT(byte[] data, byte[] Keys)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(data[i] ^ Keys[i % Keys.Length]);
            }
        }

       

        public static byte[] Protect(byte[] assemblyData)
        {
       

            string name = "NullVM";

     

            moduleDefMD = ModuleDefMD.Load(assemblyData); //load the unprotected binary in dnlib
            asmRefAdder(); //this will resolve references (dlls) such as mscorlib and any dlls the unprotected binary may use. this will be to make sure resolving methods/types/fields in another assembly can be correctly identified
            Console.WriteLine("Injecting..");
            Protection.MethodProccesor.ModuleProcessor(); //this will process the module
            Console.WriteLine("Util's Loaded!");
            var nativePath = Resources.NativeEncoderx86;
            EmbeddedResource emv = new EmbeddedResource("+/&=", (nativePath), ManifestResourceAttributes.Public);
            moduleDefMD.Resources.Add(emv);
            EmbeddedResource emv64 = new EmbeddedResource("%&=?+", (Resources.NativeEncoderx64), ManifestResourceAttributes.Public);
            moduleDefMD.Resources.Add(emv64);

            byte[] cleanConversion = File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "Runtime.dll"));

            byte[] passbytes = Encoding.UTF8.GetBytes(@"0xNull");
            RT(cleanConversion, passbytes);
            EmbeddedResource embc = new EmbeddedResource("=(0xFF)", cleanConversion, ManifestResourceAttributes.Public); //Full
            moduleDefMD.Resources.Add(embc);

            EmbeddedResource emb = new EmbeddedResource("%/?#", Resources.XorMethod, ManifestResourceAttributes.Public); //XorMethod
            moduleDefMD.Resources.Add(emb);








            TypeRef attrRef = moduleDefMD.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "CompilerGeneratedAttribute");

            var ctorRef = new MemberRefUser(moduleDefMD, ".Null0", MethodSig.CreateInstance(moduleDefMD.CorLibTypes.Void), attrRef);
            var attr = new CustomAttribute(ctorRef);
            //System.Exception();
            TypeRef attrRef2 = moduleDefMD.CorLibTypes.GetTypeRef("Decrypt.Call", "DeclareType");
            //System.Exception();


            var ctorRef2 = new MemberRefUser(moduleDefMD, ".Null0", MethodSig.CreateInstance(moduleDefMD.CorLibTypes.Void), attrRef2);


            foreach (var type in moduleDefMD.GetTypes())
            {

                if (type.Name == "<Module>")
                {

                }
                else
                {
                    continue;
                }


                foreach (var method in type.Methods)
                {




                    //if (method.Name == "AntiMonke")
                    //{
                    //    continue;
                    //}
                    //else
                    //{

                    //}

                    if (method.IsRuntimeSpecialName || method.IsSpecialName || method.Name == "Invoke") continue;
                    method.CustomAttributes.Add(attr);
                    method.Name = "<" + method.Name + ">";
                }
            }

            var methImplFlags = MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed;
            var methFlags = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.ReuseSlot | MethodAttributes.MemberAccessMask;
            var meth1 = new MethodDefUser("Null",
                        MethodSig.CreateStatic(moduleDefMD.CorLibTypes.Void),
                        methImplFlags, methFlags);

            moduleDefMD.EntryPoint.DeclaringType.Methods.Add(meth1);

            var body = new CilBody();

            meth1.Body = body;
            meth1.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Zm9vbGlzaGx5IGxvbA=="));

            meth1.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, ctorRef2));
            Random s = new Random();
            int gf = s.Next(13103, 3904345);
            meth1.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(meth1.Module.Import(typeof(string).GetMethod("get_Length"))));
            meth1.Body.Instructions.Add(Instruction.Create(OpCodes.Throw));
            meth1.Body.Instructions.Insert(1, new Instruction(OpCodes.UNKNOWN1));
            meth1.Body.Instructions.Insert(2, new Instruction(OpCodes.UNKNOWN2));
            meth1.Body.Instructions.Insert(3, Instruction.Create(OpCodes.Box, meth1.Module.Import(typeof(Math))));
            meth1.Body.Instructions.Insert(4, Instruction.Create(OpCodes.Box, meth1.Module.Import(typeof(int))));




            meth1.Body.Instructions.Insert(5, OpCodes.Call.ToInstruction(moduleDefMD.Import(typeof(string).GetMethod("get_Length"))));


          




            /* Writing */
            ModuleWriterOptions modOpts = new ModuleWriterOptions(moduleDefMD);
            modOpts.MetaDataOptions.Flags =
             MetaDataFlags
              .PreserveAll; //we need to preserve all metadata tokens, otherwise resolving tokens to methods will not match the originals
            modOpts.MetaDataLogger =
             DummyLogger
              .NoThrowInstance; //since we make an unverifiable module dnlib will throw an exception. the reason we do this is because when using publically available tools this may crash them when trying to save the module.
            MemoryStream mem = new MemoryStream();
            moduleDefMD.Write(mem, modOpts); //save the module.
            return mem.ToArray();
        }


        private static void asmRefAdder()
        {
            var asmResolver = new AssemblyResolver { EnableTypeDefCache = true };
            var modCtx = new ModuleContext(asmResolver);
            asmResolver.DefaultModuleContext = modCtx;
            var asmRefs = moduleDefMD.GetAssemblyRefs().ToList();
            moduleDefMD.Context = modCtx;
            foreach (var asmRef in asmRefs)
            {
                try
                {
                    if (asmRef == null)
                        continue;
                    var asm = asmResolver.Resolve(asmRef.FullName, moduleDefMD);
                    if (asm == null)
                        continue;
                    moduleDefMD.Context.AssemblyResolver.AddToCache(asm);

                }
                catch { }
            }
        }
    }
}
