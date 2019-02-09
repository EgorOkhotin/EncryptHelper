
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EncryptHelper.Models
{
    public class Encryption
    {
        public Encryption()
        {
            Text = "";
            Direction = "";
        }
        public string Text { get; set; }
        public string Direction { get; set; }
    }
}
