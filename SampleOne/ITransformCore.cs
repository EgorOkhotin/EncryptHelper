using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace SampleOne
{
    public interface ITransformCore
    {
        void SetKeys(string passwords);
        string Encrypt(string message);
        string Decrypt(string message);
    }
}
