using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;
using LiteDB;
using SecurityCore.Keys;

namespace SecurityCore.Loader
{
    class KeyLoader : FileLoader, IDisposable, IKeyBase
    {
        LiteDatabase _keyBase;
        const string KEYS_DIR = "storage/keys/";
        const string KEYS_FILE_NAME = "keys.db";

        public KeyLoader(SecureString password)
        {
            if(!Directory.Exists(KEYS_DIR))
                Directory.CreateDirectory(KEYS_DIR);

            var dbFile = new FileStream(KEYS_DIR + KEYS_FILE_NAME, System.IO.FileMode.OpenOrCreate, FileAccess.ReadWrite);
            _keyBase = new LiteDatabase(dbFile, password: password.ToString());
        }

        public bool IsExist(string hash)
        {
            try
            {
                LoadKey(hash);
                return true;
            }
            catch(KeyNotFoundException)
            {
                return false;
            }
            catch(NullReferenceException)
            {
                return false;
            }
        }

        public void AddKey(string hash, byte[] key)
        {
            var k = new Key(hash, key);
            SaveKey(k);
            //throw new NotImplementedException();
        }

        public byte[] GetMiddleKey(string hash)
        {
            return LoadKey(hash);
        }

        public void DeleteKeyBase()
        {
            base.DeleteFile(KEYS_DIR + KEYS_FILE_NAME);
        }

        private byte[] LoadKey(string keyName)
        {
            var key = _keyBase.GetCollection<Key>().FindOne(x => (x.Name == keyName));
            if (key.KeyBytes != null) return key.KeyBytes;
            else throw new KeyNotFoundException();
        }

        private void SaveKey(Key key)
        {
            if (!IsExist(key.Name))
            {
                var collection = _keyBase.GetCollection<Key>();
                collection.Insert(key);
            }
            else throw new ArgumentException("Already exist");
        }

        private byte[] LoadExternalKey(string filePath)
        {
            try
            {
                return LoadExternalFile(filePath);
            }
            catch
            {
                return new byte[0];
            }
        }

        private bool DeleteKey(string keyName)
        {
            var key = _keyBase.GetCollection<Key>().FindOne(x => (x.Name == keyName));
            if(key.KeyBytes != null)
            {
                var array = key.KeyBytes;
                for (int i = 0; i < array.Length; i++) array[i] = 0;
                _keyBase.GetCollection<Key>().Update(key);
                _keyBase.GetCollection<Key>().Delete(x => (x.Name == keyName));
                return true;
            }
            return false;
        }

        private List<string> AvailibleKeys()
        {
            var result = new List<string>();
            var collection = _keyBase.GetCollection<Key>();
            foreach(var k in collection.FindAll())
            {
                result.Add(k.Name);
            }
            return result;
        }

        public void Dispose()
        {
            _keyBase.Dispose();
        }

        public class Key
        {
            public Key(string name, byte[] key)
            {
                Id = 0;
                KeyBytes = key;
                Name = name;
            }

            public Key()
            {

            }

            public int Id { get; set; }
            public string Name { get; set; }
            public byte[] KeyBytes { get; set; }
        }
    }
}
