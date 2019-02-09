using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption
{
    public abstract class EncryptProvider
    {
        public int BlockSize { get; protected set; }
        public int KeySize { get; protected set; }
        public int IVSize { get; protected set; }
        public abstract ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV);
        public abstract ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV);

        protected byte[] GetKey(byte[] key)
        {
            try
            {
                return GetBytes(key, KeySize);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException("Key is too short");
            }
        }

        protected byte[] GetIv(byte[] iv)
        {
            try
            {
                return GetBytes(iv, IVSize);
            }
            catch(ArgumentException ex)
            {
                throw new ArgumentException("Iv is too short");
            }
        }

        private byte[] GetBytes(byte[] array, int count)
        {
            if (array.Length >= count)
                return array.Take(count).ToArray();
            else throw new ArgumentException("Array is too short");
        }
    }
}
