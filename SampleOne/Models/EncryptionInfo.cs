using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SampleOne.Models
{
    [Serializable]
    public class EncryptionInfo
    {
        public int PasswordsCount { get; set; }
        public string[] Passwords { get; set; }
        //public SecurityCore EncryptProvider { get; set; }
    }
}
