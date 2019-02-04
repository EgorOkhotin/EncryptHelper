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

        public void AddKey(string hash, byte[] primaryKey, byte[] middleKey, bool isStorageRegistrate = true)
        {
            if (IsValidAddParams(hash, primaryKey, middleKey))
            {
                byte[] mk = middleKey;
                if (IsExist(hash))
                    mk = _keyDB.GetMiddleKey(hash);
                else
                    _keyDB.AddKey(hash, mk);

                primaryKey.XORArrays(mk);
                _keys.Add(hash, primaryKey);              
                CorruptKey(mk);
            }
            else throw new ArgumentException("Incorrect argument(s)!");
        }

        public byte[] GetKey(string hash)
        {
            return _keys[hash];
        }

        public bool IsExist(string hash)
        {
            return _keyDB.IsExist(hash) || _keys.ContainsKey(hash);
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

        private bool IsValidAddParams(string hash, byte[] primaryKey, byte[] middleKey)
        {
            if (hash != null && primaryKey != null && middleKey != null)
            {
                return primaryKey.Length == middleKey.Length;
            }
            return false;
        }

        public void AddKey(string hash, byte[] primaryKey, byte[] middleKey)
        {
            this.AddKey(hash, primaryKey, middleKey, true);
        }
    }
}
