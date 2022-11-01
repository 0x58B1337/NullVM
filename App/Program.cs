using System;
using System.IO;
using Core;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace App
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] assemblyProtected = Protector.Protect(File.ReadAllBytes(args[0]));


            ModuleDefMD module = ModuleDefMD.Load(assemblyProtected);
           //if you want some protections on module
            MemoryStream slm = new MemoryStream();
            ModuleWriterOptions modOpts = new ModuleWriterOptions(module);


            modOpts.MetaDataOptions.Flags =

                         MetaDataFlags

                          .PreserveAll;
            modOpts.MetaDataLogger =
             DummyLogger

              .NoThrowInstance;

            module.Write(slm, modOpts);


            File.WriteAllBytes("nulled.exe", slm.ToArray());

        }
    }
}
