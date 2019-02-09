using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.Keys
{
    interface IKeyBase
    {
        bool IsExist(string hash);
        void AddKey(string hash);
        byte[] GetMiddleKey(string hash);
        void DeleteKeyBase();
    }
}
