using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.Api
{
    public interface IDiplomaticService
    {
        byte[] Encrypt(byte[] message, string filePath);
        byte[] Decrypt(byte[] message, string filePath);
    }
}
