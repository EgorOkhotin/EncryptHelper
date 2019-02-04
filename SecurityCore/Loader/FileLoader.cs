using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SecurityCore.RNG;

namespace SecurityCore.Loader
{
    class FileLoader
    {
        protected const string WORKING_DIRECTORY = "storage";
        private const int BUFFER_LENGTH = 2048;
        //Bin

        public byte[] LoadInternalFile(string fileName)
        {
            return LoadFile(GetPath(fileName));
        }

        public byte[] LoadExternalFile(string filePath)
        {
            return LoadFile(filePath);
        }

        private byte[] LoadFile(string fileName)
        {
            try
            {
                using (var file = File.Open(fileName, FileMode.Open))
                {
                    var result = new byte[file.Length];
                    file.Read(result, 0, result.Length);
                    return result;
                }
            }
            catch (FileNotFoundException ex)
            {
                //add log
                return new byte[0];
            }
        }

        public bool DeleteFile(string fileName)
        {
            try
            {
                using (var file = File.Open(GetPath(fileName), FileMode.Open))
                {
                    RNGManager rng = new RNGManager();
                    long count = file.Length;
                    file.Position = 0;
                    for (long i = 0; i < count; i++)
                        file.WriteByte(rng.GetByte());
                }
                return true;
            }
            catch (FileNotFoundException ex)
            {
                //add log
                return false;
            }
        }

        public bool SaveFile(string fileName, byte[] fileData)
        {
            try
            {
                using (var file = File.Open(GetPath(fileName), FileMode.Create))
                {
                    file.Write(fileData, 0, fileData.Length);
                }
                return true;
            }
            catch(FileNotFoundException ex)
            {
                //add log
                return false;
            }
        }

        private string GetPath(string fileName)
        {
            return Path.Combine(WORKING_DIRECTORY, fileName);
        }
    }
}
