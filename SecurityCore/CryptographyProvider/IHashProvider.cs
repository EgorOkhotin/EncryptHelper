using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.CryptographyProvider
{
    interface IHashProvider
    {
        string Hash(byte[] data);
    }
}
