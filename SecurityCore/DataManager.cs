using SecurityCore.Keys;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace SecurityCore
{
    internal class DataManager : IDataCleaner
    {
        static DataManager _singleton;
        IKeyCollector _keyCollector;

        private DataManager(IKeyCollector keyCollector)
        {
            _keyCollector = keyCollector;
        }

        public static DataManager GetInstance(IKeyCollector keyCollector)
        {
            if (_singleton == null)
            {
                var manager = new DataManager(keyCollector);
                return Interlocked.CompareExchange<DataManager>(ref manager, _singleton, _singleton);
            }
            else return _singleton;
        }

        public void ImmediatelyDataDelete()
        {
            _keyCollector.DeleteAllData();
        }
    }
}
