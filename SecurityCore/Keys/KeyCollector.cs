using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace SecurityCore.Keys
{
    internal class KeyCollector : IKeyCollector, IKeyStorage
    {
        static KeyCollector _singleton;
        Dictionary<string, byte[]> _keys;
        IKeyBase _keyDB;

        private KeyCollector(IKeyBase keyDB)
        {
            _keys = new Dictionary<string, byte[]>();
            _keyDB = keyDB;
        }

        public static KeyCollector GetInstance(IKeyBase keyBase)
        {
            if (_singleton == null)
            {
                var val = new KeyCollector(keyBase);
                return Interlocked.CompareExchange<KeyCollector>(ref val, _singleton, _singleton);
            }
            else return _singleton;
        }

        public void AddKey(string hash, byte[] primaryKey, bool isStorageRegistrate = true)
        {
            if (IsValidAddParams(hash, primaryKey))
            {
                if (isStorageRegistrate)
                {
                    if (IsExist(hash))
                        throw new ArgumentException("Key already used!");
                    else
                        _keyDB.AddKey(hash);
                }
                _keys.Add(hash, primaryKey);    
            }
            else throw new ArgumentException("Incorrect argument(s)!");
        }

        public byte[] GetKey(string hash)
        {
            return _keys[hash];
        }

        public bool IsExist(string hash)
        {
            return  _keys.ContainsKey(hash) || _keyDB.IsExist(hash);
        }

        internal void DeleteKey(string name)
        {
            if(_keys.ContainsKey(name))
            {
                var key = _keys[name];
                CorruptKey(key);
                _keys.Remove(name);
            }
        }

        public void DeleteAllData()
        {
            foreach(var k in _keys)
            {
                CorruptKey(k.Value);
            }
            _keys = null;
        }

        private void CorruptKey(byte[] key)
        {
            for(int i=0; i<key.Length; i++)
            {
                key[i] = 0;
            }
        }

        private bool IsValidAddParams(string hash, byte[] primaryKey)
        {
            return (hash != null && primaryKey != null);
        }

        public void AddKey(string hash, byte[] primaryKey)
        {
            this.AddKey(hash, primaryKey, true);
        }
    }
}
