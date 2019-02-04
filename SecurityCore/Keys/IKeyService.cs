using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Keys
{
    internal interface IKeyService : IDisposable
    {
        string AddKey(SecureString key);
        string AddNoTrackKey(SecureString key);
        byte[] GetKey(string keyHash);
    }
}
