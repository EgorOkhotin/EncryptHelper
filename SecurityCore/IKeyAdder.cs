using System;
using System.Security;

namespace SecurityCore
{
    internal interface IKeyAdder
    {
        string AddKey(SecureString key);
        string AddNoTrackKey(SecureString key);
    }
}