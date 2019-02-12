using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.CryptographyProvider
{
    internal interface ICryptographyProvider
    {
        byte[] Encrypt(byte[] message);
        byte[] Decrypt(byte[] message);
        void SetKeys(params CryptoPair[] pairs);
    }
}
