using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.Keys
{
    internal interface IKeyStorage
    {
        void AddKey(string hash, byte[] primaryKey, byte[] middleKey);
        void AddKey(string hash, byte[] primaryKey, byte[] middleKey, bool isStorageRegistrate);
        byte[] GetKey(string hash);
        bool IsExist(string hash);

    }
}
