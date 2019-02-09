using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.Keys
{
    internal interface IKeyStorage
    {
        void AddKey(string hash, byte[] primaryKey);
        void AddKey(string hash, byte[] primaryKey, bool isStorageRegistrate);
        byte[] GetKey(string hash);
        bool IsExist(string hash);

    }
}
