using SecurityCore.RNG;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace SecurityCore.CryptographyProvider
{
    abstract class CryptographyProvider : ICryptographyProvider
    {
        RNGManager _rng;
        List<string> _keyHashes;

        public CryptographyProvider()
        {
            _rng = new RNGManager();
            _keyHashes = new List<string>();
        }

        public abstract byte[] Decrypt(byte[] message);
        public abstract byte[] Encrypt(byte[] message);
        public abstract void SetKeys(params CryptoPair[] pairs);

        protected RNGManager RNG => _rng;

        protected int KeySize {get;set;}
        protected int BlockSize{get;set;}
        protected List<string> KeyHashes => _keyHashes;

        protected bool IsValidKey(CryptoPair pair)
        {
            return pair.Hash != null;
        }
        
        protected (byte[],byte[]) SplitMessage(byte[] message)
        {
            return Split(message, BlockSize);
        }

        protected byte[] GetEmptyIv()
        {
            return new byte[BlockSize];
        }

        protected byte[] GetIv()
        {
            var iv = new byte[BlockSize];
            _rng.GetBytes(iv);
            return iv;
        }

        protected byte[] AlignMessage(byte[] message)
        {
            if (message.Length % BlockSize != 0)
            {
                var cel = message.Length / BlockSize;
                var count = ((cel + 1) * BlockSize);
                byte[] buff = new byte[count];
                Array.Copy(message, buff, message.Length);
                message = buff;
            }
            return message;
        }

        protected static byte[] UnAlignMessage(byte[] message)
        {
            int i = message.Length - 1;
            while (message[i] == 0) i--;
            if ((i + 1) % 2 != 0) i++;
            return message.Take(i + 1).ToArray();
        }

        protected int GetMax(params int[] values)
        {
            return values.Max();
        }

        private (byte[],byte[]) Split(byte[] message, int length)
        {
            var iv = message.Take(length).ToArray();
            message = message.Skip(length).ToArray();
            return (iv, message);
        }

    }
}
