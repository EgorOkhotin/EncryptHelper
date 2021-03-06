﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace SecurityCore
{
    static class Extensions
    {
        public static byte[] GetBytes(this SecureString val)
        {
            var pointer = Marshal.SecureStringToBSTR(val);
            var result = Marshal.PtrToStringBSTR(pointer);
            return Encoding.Unicode.GetBytes(result);
        }

        public static void XORArrays(this byte[] arr1, byte[] arr2)
        {
            if (arr1 == null || arr2 == null) throw new NullReferenceException("Array reference is null");
            if (arr1.Length != arr2.Length) throw new ArgumentException("Arrays length are different");
            for (int i = 0; i < arr1.Length; i++)
                arr1[i] = arr1[i].XORByte(arr2[i]);
        }

        public static byte XORByte(this byte b, byte b2)
        {
            var result = b ^ b2;
            return TrimToByte(result);
        }

        private static byte TrimToByte(int val)
        {
            var count = (31 - 8);
            val = val << count;
            val = val >> count;
            return (byte)val;
        }
    }
}
