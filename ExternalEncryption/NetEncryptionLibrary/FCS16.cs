﻿using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class FCS16 : HashAlgorithm
  {
    private static ushort[] LookupTable = new ushort[256]
    {
      (ushort) 0,
      (ushort) 4489,
      (ushort) 8978,
      (ushort) 12955,
      (ushort) 17956,
      (ushort) 22445,
      (ushort) 25910,
      (ushort) 29887,
      (ushort) 35912,
      (ushort) 40385,
      (ushort) 44890,
      (ushort) 48851,
      (ushort) 51820,
      (ushort) 56293,
      (ushort) 59774,
      (ushort) 63735,
      (ushort) 4225,
      (ushort) 264,
      (ushort) 13203,
      (ushort) 8730,
      (ushort) 22181,
      (ushort) 18220,
      (ushort) 30135,
      (ushort) 25662,
      (ushort) 40137,
      (ushort) 36160,
      (ushort) 49115,
      (ushort) 44626,
      (ushort) 56045,
      (ushort) 52068,
      (ushort) 63999,
      (ushort) 59510,
      (ushort) 8450,
      (ushort) 12427,
      (ushort) 528,
      (ushort) 5017,
      (ushort) 26406,
      (ushort) 30383,
      (ushort) 17460,
      (ushort) 21949,
      (ushort) 44362,
      (ushort) 48323,
      (ushort) 36440,
      (ushort) 40913,
      (ushort) 60270,
      (ushort) 64231,
      (ushort) 51324,
      (ushort) 55797,
      (ushort) 12675,
      (ushort) 8202,
      (ushort) 4753,
      (ushort) 792,
      (ushort) 30631,
      (ushort) 26158,
      (ushort) 21685,
      (ushort) 17724,
      (ushort) 48587,
      (ushort) 44098,
      (ushort) 40665,
      (ushort) 36688,
      (ushort) 64495,
      (ushort) 60006,
      (ushort) 55549,
      (ushort) 51572,
      (ushort) 16900,
      (ushort) 21389,
      (ushort) 24854,
      (ushort) 28831,
      (ushort) 1056,
      (ushort) 5545,
      (ushort) 10034,
      (ushort) 14011,
      (ushort) 52812,
      (ushort) 57285,
      (ushort) 60766,
      (ushort) 64727,
      (ushort) 34920,
      (ushort) 39393,
      (ushort) 43898,
      (ushort) 47859,
      (ushort) 21125,
      (ushort) 17164,
      (ushort) 29079,
      (ushort) 24606,
      (ushort) 5281,
      (ushort) 1320,
      (ushort) 14259,
      (ushort) 9786,
      (ushort) 57037,
      (ushort) 53060,
      (ushort) 64991,
      (ushort) 60502,
      (ushort) 39145,
      (ushort) 35168,
      (ushort) 48123,
      (ushort) 43634,
      (ushort) 25350,
      (ushort) 29327,
      (ushort) 16404,
      (ushort) 20893,
      (ushort) 9506,
      (ushort) 13483,
      (ushort) 1584,
      (ushort) 6073,
      (ushort) 61262,
      (ushort) 65223,
      (ushort) 52316,
      (ushort) 56789,
      (ushort) 43370,
      (ushort) 47331,
      (ushort) 35448,
      (ushort) 39921,
      (ushort) 29575,
      (ushort) 25102,
      (ushort) 20629,
      (ushort) 16668,
      (ushort) 13731,
      (ushort) 9258,
      (ushort) 5809,
      (ushort) 1848,
      (ushort) 65487,
      (ushort) 60998,
      (ushort) 56541,
      (ushort) 52564,
      (ushort) 47595,
      (ushort) 43106,
      (ushort) 39673,
      (ushort) 35696,
      (ushort) 33800,
      (ushort) 38273,
      (ushort) 42778,
      (ushort) 46739,
      (ushort) 49708,
      (ushort) 54181,
      (ushort) 57662,
      (ushort) 61623,
      (ushort) 2112,
      (ushort) 6601,
      (ushort) 11090,
      (ushort) 15067,
      (ushort) 20068,
      (ushort) 24557,
      (ushort) 28022,
      (ushort) 31999,
      (ushort) 38025,
      (ushort) 34048,
      (ushort) 47003,
      (ushort) 42514,
      (ushort) 53933,
      (ushort) 49956,
      (ushort) 61887,
      (ushort) 57398,
      (ushort) 6337,
      (ushort) 2376,
      (ushort) 15315,
      (ushort) 10842,
      (ushort) 24293,
      (ushort) 20332,
      (ushort) 32247,
      (ushort) 27774,
      (ushort) 42250,
      (ushort) 46211,
      (ushort) 34328,
      (ushort) 38801,
      (ushort) 58158,
      (ushort) 62119,
      (ushort) 49212,
      (ushort) 53685,
      (ushort) 10562,
      (ushort) 14539,
      (ushort) 2640,
      (ushort) 7129,
      (ushort) 28518,
      (ushort) 32495,
      (ushort) 19572,
      (ushort) 24061,
      (ushort) 46475,
      (ushort) 41986,
      (ushort) 38553,
      (ushort) 34576,
      (ushort) 62383,
      (ushort) 57894,
      (ushort) 53437,
      (ushort) 49460,
      (ushort) 14787,
      (ushort) 10314,
      (ushort) 6865,
      (ushort) 2904,
      (ushort) 32743,
      (ushort) 28270,
      (ushort) 23797,
      (ushort) 19836,
      (ushort) 50700,
      (ushort) 55173,
      (ushort) 58654,
      (ushort) 62615,
      (ushort) 32808,
      (ushort) 37281,
      (ushort) 41786,
      (ushort) 45747,
      (ushort) 19012,
      (ushort) 23501,
      (ushort) 26966,
      (ushort) 30943,
      (ushort) 3168,
      (ushort) 7657,
      (ushort) 12146,
      (ushort) 16123,
      (ushort) 54925,
      (ushort) 50948,
      (ushort) 62879,
      (ushort) 58390,
      (ushort) 37033,
      (ushort) 33056,
      (ushort) 46011,
      (ushort) 41522,
      (ushort) 23237,
      (ushort) 19276,
      (ushort) 31191,
      (ushort) 26718,
      (ushort) 7393,
      (ushort) 3432,
      (ushort) 16371,
      (ushort) 11898,
      (ushort) 59150,
      (ushort) 63111,
      (ushort) 50204,
      (ushort) 54677,
      (ushort) 41258,
      (ushort) 45219,
      (ushort) 33336,
      (ushort) 37809,
      (ushort) 27462,
      (ushort) 31439,
      (ushort) 18516,
      (ushort) 23005,
      (ushort) 11618,
      (ushort) 15595,
      (ushort) 3696,
      (ushort) 8185,
      (ushort) 63375,
      (ushort) 58886,
      (ushort) 54429,
      (ushort) 50452,
      (ushort) 45483,
      (ushort) 40994,
      (ushort) 37561,
      (ushort) 33584,
      (ushort) 31687,
      (ushort) 27214,
      (ushort) 22741,
      (ushort) 18780,
      (ushort) 15843,
      (ushort) 11370,
      (ushort) 7921,
      (ushort) 3960
    };
    protected int State;
    private ushort hash;

    public override int HashSize
    {
      get
      {
        return 16;
      }
    }

    public FCS16()
    {
      lock (this)
        this.Initialize();
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
      lock (this)
      {
        for (int index = ibStart; index < ibStart + cbSize; ++index)
          this.hash = (ushort) ((uint) this.hash >> 8 ^ (uint) FCS16.LookupTable[((int) this.hash ^ (int) array[index]) & (int) byte.MaxValue]);
      }
    }

    protected override byte[] HashFinal()
    {
      lock (this)
        return Utilities.UShortToByte(this.hash, EndianType.BigEndian);
    }

    public override void Initialize()
    {
      lock (this)
      {
        this.State = 0;
        this.hash = ushort.MaxValue;
      }
    }
  }
}
