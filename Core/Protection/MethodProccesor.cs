using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using Core.Injection;

namespace Core.Protection
{
    internal class MethodProccesor
    {
        public static List<MethodData> AllMethods = new List<MethodData>();
      static  string EncryptOrDecrypt(string text, string key)
        {
            var result = new StringBuilder();

            for (int c = 0; c < text.Length; c++)
                result.Append((char)((uint)text[c] ^ (uint)key[c % key.Length]));

            return result.ToString();
        }
        public static void ModuleProcessor()
        {

            Injection.InjectInitialise.initaliseMethod();

            int value = 0;
            foreach (var typeDef in Protector.moduleDefMD.GetTypes())
            {
                if (typeDef == Protector.moduleDefMD.GlobalType) continue;

                if (typeDef.HasGenericParameters) continue;

                //		if (!typeDef.FullName.Contains("MainWindow")) continue;
                if (typeDef.CustomAttributes.Count(i => i.TypeFullName.Contains("CompilerGenerated")) != 0) continue;
                if (typeDef.IsValueType) continue;
                foreach (var method in typeDef.Methods)
                {
                    //if (method.MDToken.ToInt32() != 0x0600017E) continue;
                    //	if (Protector.moduleDefMD.EntryPoint != method) continue;
                    if (method.IsConstructor) continue;
                    if (!CanBeProtected(method)) continue;//check to see if we can protect the method
                    if (!method.HasBody) continue;
                    if (typeDef.IsGlobalModuleType && method.IsConstructor) continue;
                    if (method.HasGenericParameters) continue;
                    if (method.CustomAttributes.Count(i => i.TypeFullName.Contains("CompilerGenerated")) != 0) continue;
                    if (method.ReturnType == null) continue;
                    if (method
                     .ReturnType.IsGenericParameter) continue;

                    if (method.Parameters.Count(i => i.Type.FullName.EndsWith("&") && i.ParamDef.IsOut == false) != 0) continue;
                    if (method.CustomAttributes.Count(i => i.NamedArguments.Count == 2 &&
                                                            i.NamedArguments[0].Value.ToString().Contains("Encrypt") &&
                                                            i.NamedArguments[1].Name.Contains("Exclude") && i.NamedArguments[1].Value
                                                             .ToString().ToLower().Contains("true")) != 0) continue;
                    MethodData methodData = new MethodData(method);//create instance of custom class

                    method.Body.SimplifyMacros(method.Parameters);
                    method.Body.SimplifyBranches();
                    var convertor = new ConvertToBytes(method);
                    try
                    {
                        convertor.ConversionMethod();//we convert our method to byte array

                        if (!convertor.Successful) continue;//only carry on if the conversion was successful
                        methodData.Converted = true;//set conversion to true 
                        methodData.DecryptedBytes = convertor.ConvertedBytes;//set methodData bytes to the coverted bytes
                        methodData.ID = value;//set the methodID
                        AllMethods.Add(methodData);
                        value++;//increase value which is methodID
                    }
                    catch
                    {

                    }




                }
            }



            Injection.InjectInitialise.injectIntoCctor("$%!&");//inject the setup methods into the module cctor which is the very first method that is executed in the .net module
            Injection.InjectMethods.methodInjector();//inject the methods to remove the old code and add the call to the decryption
                                                     //if ((Protector.moduleDefMD.Characteristics & Characteristics.Dll) == 0)
                                                     //{
                                                     //	var vody = Protector.moduleDefMD.EntryPoint.Body;
                                                     //	vody.Instructions.Insert(0, new Instruction(OpCodes.Ldstr, "TestResc"));
                                                     //	vody.Instructions.Insert(1, new Instruction(OpCodes.Call, InjectInitialise.conversionInit));
                                                     //}
            if ((Protector.moduleDefMD.Characteristics & Characteristics.Dll) == 0)
            {
                bool set = false;
                var vody = Protector.moduleDefMD.GlobalType.FindOrCreateStaticConstructor().Body;
                for (int i = 1; i < vody.Instructions.Count; i++)
                {
                    if (vody.Instructions[i].OpCode == OpCodes.Call)
                    {
                        MethodDef method = (MethodDef)vody.Instructions[i].Operand;
                        method.Body.Instructions.Insert(0, new Instruction(OpCodes.Ldstr, EncryptOrDecrypt("$%!&", "0x58B_")));

                        method.Body.Instructions.Insert(1, new Instruction(OpCodes.Call, InjectInitialise.conversionInit));
                        set = true;
                        break;
                    }
                }
                if (set == false)
                {
                    var vody2 = Protector.moduleDefMD.EntryPoint.Body;
                    vody2.Instructions.Insert(0, new Instruction(OpCodes.Ldstr, EncryptOrDecrypt("$%!&", "0x58B_")));

                    vody2.Instructions.Insert(1, new Instruction(OpCodes.Call, InjectInitialise.conversionInit));
                }
            }

            ByteEncryption.Process.processConvertedMethods(AllMethods);
            List<byte> allBytes = new List<byte>();
            foreach (var meth in AllMethods)
            {
                allBytes.AddRange(meth.EncryptedBytes);//add all bytes of all methods into one byte array
            }
            byte[] bytesName = Encoding.ASCII.GetBytes("Null");
            bytesName = ByteEncryption.ByteEncryption.Encrypt(new byte[] { 0xBB, 0xAA, 0x32, 0x75, 0xc6, 0x42, 0x70, 0x24, 0x00, 0xcc, 12, 54, 66, 34, 23, 65 }, bytesName);
            allBytes.AddRange(bytesName);
            byte[] tester2 = exclusiveOR(allBytes.ToArray());
            //	byte[] decrypted = exclusiveOR(tester2, File.ReadAllBytes(Protector.path2));

            EmbeddedResource emb = new EmbeddedResource("$%!&", tester2);//create an embededd resource which we add to module later

            Protector.moduleDefMD.Resources.Add(emb);//add to module

        }
        public static byte[] exclusiveOR(byte[] arr1)
        {

            Random rand = new Random(23546654);

            byte[] result = new byte[arr1.Length];
            for (int i = 0; i < arr1.Length; i++)
            {
                result[i] = (byte)(arr1[i] ^ rand.Next(0, 250));
            }


            return result;
        }

        private static bool CanBeProtected(MethodDef method)
        {
            //if method has body we can protect
            //if its a globalModuleType we have possible issues since reflection has fail safes meaning we cant resolve to this module
            return method.HasBody || !method.DeclaringType.IsGlobalModuleType;
        }
    }
}