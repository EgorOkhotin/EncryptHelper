using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.CryptographyProvider.Algos
{
    interface ICryptographyAlgorithm
    {
        byte[] Encrypt(byte[] message, byte[] key, byte[] iv);
        byte[] Decrypt(byte[] message, byte[] key, byte[] iv);

        int KeyByteSize {get;}
        int BlockByteSize{get;}
    }
}
