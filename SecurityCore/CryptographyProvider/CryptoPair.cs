using System;
using System.Collections.Generic;
using System.Text;
using SecurityCore.CryptographyProvider.Algos;

namespace SecurityCore.CryptographyProvider
{
    struct CryptoPair
    {
        readonly ICryptographyAlgorithm alg;
        readonly string hashKey;

        public CryptoPair(ICryptographyAlgorithm alg, string hashKey)
        {
            this.alg = alg;
            this.hashKey = hashKey;
        }

        public ICryptographyAlgorithm Algorithm => alg;
        public string Hash => hashKey;
    }
}
