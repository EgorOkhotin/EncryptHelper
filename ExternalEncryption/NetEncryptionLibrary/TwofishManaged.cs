using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
    public sealed class TwofishManaged : SymmetricAlgorithm
    {

        /// <summary>
        /// Initializes a new instance.
        /// </summary>
        public TwofishManaged()
            : base()
        {
            base.KeySizeValue = 256;
            base.BlockSizeValue = 128;
            base.FeedbackSizeValue = base.BlockSizeValue;
            base.LegalBlockSizesValue = new KeySizes[] { new KeySizes(128, 128, 0) };
            base.LegalKeySizesValue = new KeySizes[] { new KeySizes(128, 256, 64) };

            base.Mode = CipherMode.CBC; //same as default
            base.Padding = PaddingMode.PKCS7;
        }


        /// <summary>
        /// Creates a symmetric decryptor object.
        /// </summary>
        /// <param name="rgbKey">The secret key to be used for the symmetric algorithm. The key size must be 128, 192, or 256 bits.</param>
        /// <param name="rgbIV">The IV to be used for the symmetric algorithm.</param>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null) { throw new ArgumentNullException("rgbKey", "Key cannot be null."); }
            if (rgbKey.Length != KeySize / 8) { throw new ArgumentOutOfRangeException("rgbKey", "Key size mismatch."); }
            if (Mode == CipherMode.CBC)
            {
                if (rgbIV == null) { throw new ArgumentNullException("rgbIV", "IV cannot be null."); }
                if (rgbIV.Length != 16) { throw new ArgumentOutOfRangeException("rgbIV", "Invalid IV size."); }
            }

            return NewEncryptor(rgbKey, Mode, rgbIV, TwofishManagedTransformMode.Decrypt);
        }

        /// <summary>
        /// Creates a symmetric encryptor object.
        /// </summary>
        /// <param name="rgbKey">The secret key to be used for the symmetric algorithm. The key size must be 128, 192, or 256 bits.</param>
        /// <param name="rgbIV">The IV to be used for the symmetric algorithm.</param>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null) { throw new ArgumentNullException("rgbKey", "Key cannot be null."); }
            if (rgbKey.Length != KeySize / 8) { throw new ArgumentOutOfRangeException("rgbKey", "Key size mismatch."); }
            if (Mode == CipherMode.CBC)
            {
                if (rgbIV == null) { throw new ArgumentNullException("rgbIV", "IV cannot be null."); }
                if (rgbIV.Length != 16) { throw new ArgumentOutOfRangeException("rgbIV", "Invalid IV size."); }
            }

            return NewEncryptor(rgbKey, Mode, rgbIV, TwofishManagedTransformMode.Encrypt);
        }

        /// <summary>
        /// Generates a random initialization vector to be used for the algorithm.
        /// </summary>
        public override void GenerateIV()
        {
            IVValue = new byte[FeedbackSizeValue / 8];
            Rng.Value.GetBytes(IVValue);
        }

        /// <summary>
        /// Generates a random key to be used for the algorithm.
        /// </summary>
        public override void GenerateKey()
        {
            KeyValue = new byte[KeySizeValue / 8];
            Rng.Value.GetBytes(KeyValue);
        }


        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public override CipherMode Mode
        {
            get { return base.Mode; }
            set
            {
                if ((value != CipherMode.CBC) && (value != CipherMode.ECB))
                {
                    throw new CryptographicException("Cipher mode is not supported.");
                }
                base.Mode = value;
            }
        }

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public override PaddingMode Padding
        {
            get { return base.Padding; }
            set
            {
                switch (value)
                {
                    case PaddingMode.None:
                    case PaddingMode.PKCS7:
                    case PaddingMode.Zeros:
                    case PaddingMode.ANSIX923:
                    case PaddingMode.ISO10126:
                        base.Padding = value;
                        break;
                    default: throw new CryptographicException("Padding mode is not supported.");
                }
            }
        }


        #region Private

        private static Lazy<RandomNumberGenerator> Rng = new Lazy<RandomNumberGenerator>(() => RandomNumberGenerator.Create());

        private ICryptoTransform NewEncryptor(byte[] rgbKey, CipherMode mode, byte[] rgbIV, TwofishManagedTransformMode encryptMode)
        {
            if (rgbKey == null)
            {
                rgbKey = new byte[KeySize / 8];
                Rng.Value.GetBytes(rgbKey);
            }

            if ((mode != CipherMode.ECB) && (rgbIV == null))
            {
                rgbIV = new byte[KeySize / 8];
                Rng.Value.GetBytes(rgbIV);
            }

            return new TwofishManagedTransform(rgbKey, mode, rgbIV, encryptMode, Padding);
        }

        #endregion

    }


}
