
using NullVM;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
//use FrameWork 2.0 for compatibility on older files
namespace NullVM
{
    public class Null
    {

       


        public static object locker2 = new object();

        public static string Base64(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
        public static string DecryptStr(string text)
        {
            var result = new StringBuilder();

            for (int c = 0; c < text.Length; c++)
                result.Append((char)((uint)text[c] ^ (uint)"0x58B^/"[c % "0x58B^/".Length]));

            return result.ToString();
        }
        public static object Invoke64(string values, object[] parameters, object obj)
        {




            string slm = DecryptStr(values);
           string[] hey = slm.Split('-');
           int id = Convert.ToInt32(hey[2]);





            DynamicMethod value;

            if (cache.TryGetValue(id, out value))//Check cache to see if method has already been created
            {
                return value.Invoke(null, parameters);//if it has directly invoke the method instead of converting it to dynamicmethod
            }
            else
            {
             

                MethodBase callingMethod = new StackTrace().GetFrame(1).GetMethod();//get calling method, using this can prevent invocation and dynamic unpacking
                int p = Convert.ToInt32(hey[1]);
                int s = Convert.ToInt32(hey[0]);
                var grabbedBytes = byteArrayGrabber(MethodReady.byteArrayResource, p, s);
                var decryptionKey = MD5.Create().ComputeHash(Encoding.ASCII.GetBytes(callingMethod.Name + hey[2]));
                var ab = callingMethod.GetMethodBody().GetILAsByteArray();
                
                MethodReady.bc(grabbedBytes, grabbedBytes.Length, ab, ab.Length);
                var decrypted = Decrypt(decryptionKey, grabbedBytes);

              


                return ConversionBack(decrypted, id, parameters, callingMethod);//if not convert the method to a dynamic method
            }
        }


        public static object ConversionBack(byte[] bytes, int ID, object[] parameters, MethodBase callingMethod)
        {


            MethodBody methodBody = callingMethod.GetMethodBody();//get calling methods body 
            BinaryReader binaryReader = new BinaryReader(new MemoryStream(bytes));//cast byte[] Position


            var methodParameters = callingMethod.GetParameters();//get its parameters
            var allLocals = new List<LocalBuilder>();
         
            Type[] parametersArray;
            int start = 0;
            if (callingMethod.IsStatic)//check if the method is static or not
            {
                parametersArray = new Type[methodParameters.Length];//if method is static set the parameters to the amount in calling method
            }
            else
            {
                parametersArray = new Type[methodParameters.Length + 1];//if its not static this means there is an additional hidden parameter (this.) this is always used as the first parameter so we need to account for this
                parametersArray[0] = callingMethod.DeclaringType;
                start = 1;
            }
            for (var i = 0; i < methodParameters.Length; i++)
            {
                var parameterInfo = methodParameters[i];
                parametersArray[start + i] = parameterInfo.ParameterType;//set parameter types
            }
            DynamicMethod dynamicMethod = new DynamicMethod("0x58B", callingMethod.MemberType == MemberTypes.Constructor ? null : ((MethodInfo)callingMethod).ReturnParameter.ParameterType, parametersArray, MethodReady.callingModule, true);//create the dynamic method
            ILGenerator ilGenerator = dynamicMethod.GetILGenerator();//get ilgenerator
            var locs = methodBody.LocalVariables;
            var locals = new Type[locs.Count];
            foreach (var localVariableInfo in locs)
                allLocals.Add(ilGenerator.DeclareLocal(localVariableInfo.LocalType));//declare the local for use of stloc,ldloc/ldloca
            var exceptionHandlersCount = binaryReader.ReadInt32();//read amount of exception handlers
           
            var instructionCount = binaryReader.ReadInt32();//read the amount of instructions
            var _allLabelsDictionary = new Dictionary<int, Label>();

            for (var u = 0; u < instructionCount; u++)
            {
                var label = ilGenerator.DefineLabel();//we need to label each instruction to use with branches

                _allLabelsDictionary.Add(u, label);
            }


            for (var i = 0; i < instructionCount; i++)
            {
               
                var opcode = binaryReader.ReadInt16();//read opcode short this will relate to the correct opcode
                OpCode opc;
                if (opcode >= 0 && opcode < MethodReady.oneByteOpCodes.Length)
                {
                    opc = MethodReady.oneByteOpCodes[opcode];//we check against one byte opcodes
                }
                else
                {
                    var b2 = (byte)(opcode | 0xFE00);
                    opc = MethodReady.twoByteOpCodes[b2];//check against two byte opcodes
                }

                ilGenerator.MarkLabel(_allLabelsDictionary[i]);//we now need to mark the label in the ilgenerator
                var operandType = binaryReader.ReadByte();//we get the operand type

                HandleOpType(operandType, opc, ilGenerator, binaryReader, _allLabelsDictionary, allLocals);//we process the instruction with ilgenerator
            }
            lock (locker)//we lock threads here to prevent exceptions of item already exists
            {
                if (!cache.ContainsKey(ID))
                {
                    cache.Add(ID, dynamicMethod);//add to cache if first time creating method
                }
            }

            return dynamicMethod.Invoke(null, parameters);//invoke the dynamic method which is the users original method and return the result
        }
        public static object locker = new object();
        public static Dictionary<int, DynamicMethod> cache = new Dictionary<int, DynamicMethod>();

        /// <summary>
        /// We handle operand type and convert this to a real instruction
        /// </summary>
        /// <param name="opType"></param>
        /// <param name="opcode"></param>
        /// <param name="ilGenerator"></param>
        /// <param name="binaryReader"></param>
        /// <param name="_allLabelsDictionary"></param>
        /// <param name="allLocals"></param>
        private static void HandleOpType(int opType, OpCode opcode, ILGenerator ilGenerator, BinaryReader binaryReader, Dictionary<int, Label> _allLabelsDictionary, List<LocalBuilder> allLocals)
        {
            switch (opType)//we switch on operand type
            {
                case 0:
                    InlineNoneEmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 1:
                    InlineMethodEmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 2:
                    InlineStringEmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 3:
                    InlineIEmitter(ilGenerator, opcode, binaryReader);
                    break;

                case 5:
                    InlineFieldEmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 6:
                    InlineTypeEmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 7:
                    ShortInlineBrTargetEmitter(ilGenerator, opcode, binaryReader, _allLabelsDictionary);
                    break;
                case 8:
                    ShortInlineIEmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 9:
                    InlineSwitchEmitter(ilGenerator, opcode, binaryReader, _allLabelsDictionary);
                    break;
                case 10:
                    InlineBrTargetEmitter(ilGenerator, opcode, binaryReader, _allLabelsDictionary);
                    break;
                case 11:
                    InlineTokEmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 12:
                case 4:
                    InlineVarEmitter(ilGenerator, opcode, binaryReader, allLocals);
                    break;
                case 13:
                    ShortInlineREmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 14:
                    InlineREmitter(ilGenerator, opcode, binaryReader);
                    break;
                case 15:
                    InlineI8Emitter(ilGenerator, opcode, binaryReader);
                    break;
                default:
                    throw new Exception("Operand Type Unknown " + opType);
            }
        }
        /// <summary>
        /// this operand type does nothing it is for opcodes that have no operands
        /// </summary>
        /// <param name="ilGenerator"></param>
        /// <param name="opcode"></param>
        /// <param name="binaryReader"></param>
        private static void InlineNoneEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader)
        {
            ilGenerator.Emit(opcode);
        }

        /// <summary>
        /// this is for calling of methods where it will resolve the metadata token that relates to the method
        /// </summary>
        /// <param name="ilGenerator"></param>
        /// <param name="opcode"></param>
        /// <param name="binaryReader"></param>
        private static void InlineMethodEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader)
        {
            var mdtoken = binaryReader.ReadInt32();
            var resolvedMethodBase = MethodReady.callingModule.ResolveMethod(mdtoken);
            if (resolvedMethodBase is MethodInfo)
                ilGenerator.Emit(opcode, (MethodInfo)resolvedMethodBase);
            else if (resolvedMethodBase is ConstructorInfo)
                ilGenerator.Emit(opcode, (ConstructorInfo)resolvedMethodBase);
            else
                throw new Exception("Check resolvedMethodBase Type");
        }
        /// <summary>
        /// This is for operands that handle variables and parameters we need to emit the label that it relates to which we defined earlier
        /// </summary>
        /// <param name="ilGenerator"></param>
        /// <param name="opcode"></param>
        /// <param name="binaryReader"></param>
        /// <param name="allLocals"></param>
        private static void InlineVarEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader, List<LocalBuilder> allLocals)
        {
            var index = binaryReader.ReadInt32();
            var parOrloc = binaryReader.ReadByte();
            if (parOrloc == 0)
            {
                var label = allLocals[index];
                ilGenerator.Emit(opcode, label);
            }
            else
            {
                ilGenerator.Emit(opcode, index);
            }

        }

        /// <summary>
        /// read the string from the byte[] and emit the opcode with this string
        /// </summary>
        /// <param name="ilGenerator"></param>
        /// <param name="opcode"></param>
        /// <param name="binaryReader"></param>
        private static void InlineStringEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader)
        {
            var readString = binaryReader.ReadString();
            ilGenerator.Emit(opcode, readString);
        }
        private static void InlineIEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader)
        {
            var readInt32 = binaryReader.ReadInt32();

            ilGenerator.Emit(opcode, readInt32);
        }

        private static void InlineFieldEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader)
        {
            int mdtoken = binaryReader.ReadInt32();
            FieldInfo fieldInfo = MethodReady.callingModule.ResolveField(mdtoken);
            ilGenerator.Emit(opcode, fieldInfo);
        }

        private static void InlineTypeEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader)
        {
            int mdtoken = binaryReader.ReadInt32();
            Type type = MethodReady.callingModule.ResolveType(mdtoken);
            ilGenerator.Emit(opcode, type);
        }

        private static void ShortInlineBrTargetEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader, Dictionary<int, Label> _allLabelsDictionary)
        {
            int index = binaryReader.ReadInt32();
            var location = _allLabelsDictionary[index];
            ilGenerator.Emit(opcode, location);
        }

        private static void ShortInlineIEmitter(ILGenerator ilGenerator, OpCode opCode, BinaryReader binaryReader)
        {
            byte b = binaryReader.ReadByte();
            ilGenerator.Emit(opCode, b);
        }
        private static void ShortInlineREmitter(ILGenerator ilGenerator, OpCode opCode, BinaryReader binaryReader)
        {
            var value = binaryReader.ReadBytes(4);
            var myFloat = BitConverter.ToSingle(value, 0);
            ilGenerator.Emit(opCode, myFloat);
        }
        private static void InlineREmitter(ILGenerator ilGenerator, OpCode opCode, BinaryReader binaryReader)
        {
            var value = binaryReader.ReadDouble();

            ilGenerator.Emit(opCode, value);
        }
        private static void InlineI8Emitter(ILGenerator ilGenerator, OpCode opCode, BinaryReader binaryReader)
        {
            var value = binaryReader.ReadInt64();

            ilGenerator.Emit(opCode, value);
        }

        private static void InlineSwitchEmitter(ILGenerator ilGenerator, OpCode opCode, BinaryReader binaryReader, Dictionary<int, Label> _allLabelsDictionary)
        {
            int count = binaryReader.ReadInt32();
            Label[] allLabels = new Label[count];
            for (int i = 0; i < count; i++)
            {
                allLabels[i] = _allLabelsDictionary[binaryReader.ReadInt32()];

            }
            ilGenerator.Emit(opCode, allLabels);
        }
        private static void InlineBrTargetEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader, Dictionary<int, Label> _allLabelsDictionary)
        {
            int index = binaryReader.ReadInt32();
            var location = _allLabelsDictionary[index];
            ilGenerator.Emit(opcode, location);
        }

        private static void InlineTokEmitter(ILGenerator ilGenerator, OpCode opcode, BinaryReader binaryReader)
        {
            int mdtoken = binaryReader.ReadInt32();
            byte type = binaryReader.ReadByte();
            if (type == 0)
            {
                var fieldinfo = MethodReady.callingModule.ResolveField(mdtoken);
                ilGenerator.Emit(opcode, fieldinfo);
            }
            else if (type == 1)
            {
                var typeInfo = MethodReady.callingModule.ResolveType(mdtoken);
                ilGenerator.Emit(opcode, typeInfo);
            }
            else if (type == 2)
            {
                var methodinfo = MethodReady.callingModule.ResolveMethod(mdtoken);
                if (methodinfo is MethodInfo)
                    ilGenerator.Emit(opcode, (MethodInfo)methodinfo);
                else if (methodinfo is ConstructorInfo)
                    ilGenerator.Emit(opcode, (ConstructorInfo)methodinfo);
            }
        }

      
  
        public static byte[] byteArrayGrabber(byte[] bytes, int skip, int take)
        {
            byte[] newBarray = new byte[take];
            int y = 0;
            for (int i = 0; i < take; i++, y++)
            {
                byte curByte = bytes[skip + i];
                newBarray[y] = curByte;
            }

            return newBarray;

        }
        private static byte[] DecryptBytes(
           SymmetricAlgorithm alg,
           byte[] message)
        {
            if (message == null || message.Length == 0)
                return message;

            if (alg == null)
                throw new ArgumentNullException("alg is null");

            using (var stream = new MemoryStream())
            using (var decryptor = alg.CreateDecryptor())
            using (var encrypt = new CryptoStream(stream, decryptor, CryptoStreamMode.Write))
            {
                encrypt.Write(message, 0, message.Length);
                encrypt.FlushFinalBlock();
                return stream.ToArray();
            }
        }
        public static byte[] Decrypt(byte[] key, byte[] message)
        {
            using (var rijndael = new RijndaelManaged())
            {
                rijndael.Key = key;
                rijndael.IV = key;
                return DecryptBytes(rijndael, message);
            }
        }
    }
}
