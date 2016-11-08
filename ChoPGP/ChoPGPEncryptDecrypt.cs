using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cinchoo.PGP
{
    public class ChoPGPEncryptDecrypt : IDisposable
    {
        public static readonly ChoPGPEncryptDecrypt Default = new ChoPGPEncryptDecrypt();

        private const int BufferSize = 0x10000;

        public CompressionAlgorithmTag CompressionAlgorithmTag
        {
            get;
            set;
        }

        #region Constructor

        public ChoPGPEncryptDecrypt()
        {
            CompressionAlgorithmTag = CompressionAlgorithmTag.Zip;
        }

        #endregion Constructor

        #region Encrypt

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        public void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyFilePath,
            bool armor, bool withIntegrityCheck)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(String.Format("Public Key file [{0}] does not exist.", publicKeyFilePath));

            using (Stream pkStream = File.OpenRead(publicKeyFilePath))
            {
                using (MemoryStream @out = new MemoryStream())
                {
                    PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag);
                    PgpUtilities.WriteFileToLiteralData(comData.Open(@out), PgpLiteralData.Binary, new FileInfo(inputFilePath));
                    comData.Close();

                    PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                    pk.AddMethod(ReadPublicKey(pkStream));

                    byte[] bytes = @out.ToArray();

                    using (Stream outStream = File.Create(outputFilePath))
                    {
                        if (armor)
                        {
                            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outStream))
                            {
                                using (Stream armoredOutStream = pk.Open(armoredStream, bytes.Length))
                                {
                                    armoredOutStream.Write(bytes, 0, bytes.Length);
                                }
                            }
                        }
                        else
                        {
                            using (Stream plainStream = pk.Open(outStream, bytes.Length))
                            {
                                plainStream.Write(bytes, 0, bytes.Length);
                            }
                        }
                    }
                }
            }
        }

        #endregion Encrypt

        #region Encrypt and Sign

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, string publicKeyFilePath,
            string privateKeyFilePath, string passPhrase, bool armor)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (String.IsNullOrEmpty(passPhrase))
                throw new ArgumentNullException("Invalid Pass Phrase.");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(String.Format("Public Key file [{0}] does not exist.", publicKeyFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(String.Format("Private Key file [{0}] does not exist.", privateKeyFilePath));

            ChoPGPEncryptionKeys encryptionKeys = new ChoPGPEncryptionKeys(publicKeyFilePath, privateKeyFilePath, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputEncrypted(inputFilePath, armoredOutputStream, encryptionKeys);
                    }
                }
                else
                    OutputEncrypted(inputFilePath, outputStream, encryptionKeys);
            }
        }

        private static void OutputEncrypted(string inputFilePath, Stream outputStream, ChoPGPEncryptionKeys encryptionKeys)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, encryptionKeys))
            {
                FileInfo unencryptedFileInfo = new FileInfo(inputFilePath);
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
                    using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                    {
                        using (FileStream inputFileStream = unencryptedFileInfo.OpenRead())
                        {
                            WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                            inputFileStream.Close();
                        }
                    }
                }
            }
        }

        private static void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = inputFilePath.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            signatureGenerator.Generate().Encode(compressedOut);
        }

        private static Stream ChainEncryptedOut(Stream outputStream, ChoPGPEncryptionKeys encryptionKeys)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes, new SecureRandom());
            encryptedDataGenerator.AddMethod(encryptionKeys.PublicKey);
            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        private static Stream ChainCompressedOut(Stream encryptedOut)
        {
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            return compressedDataGenerator.Open(encryptedOut);
        }

        private static Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, PgpLiteralData.Binary, file);
        }

        private static PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, ChoPGPEncryptionKeys encryptionKeys)
        {
            PublicKeyAlgorithmTag tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, encryptionKeys.PrivateKey);
            foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }
            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
            return pgpSignatureGenerator;
        }

        #endregion Encrypt and Sign

        #region Decrypt

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        public void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (String.IsNullOrEmpty(passPhrase))
                throw new ArgumentNullException("Invalid Pass Phrase.");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            {
                using (Stream keyStream = File.OpenRead(privateKeyFilePath))
                {
                    using (Stream outStream = File.Create(outputFilePath))
                        Decrypt(inputStream, outStream, keyStream, passPhrase);
                }
            }
        }

        /*
        * PGP decrypt a given stream.
        */
        private void Decrypt(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("outputStream");
            if (privateKeyStream == null)
                throw new ArgumentException("privateKeyStream");
            if (String.IsNullOrEmpty(passPhrase))
                throw new ArgumentNullException("Invalid Pass Phrase.");

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            if (obj is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)obj;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (privateKey == null)
                throw new ArgumentException("Secret key for message not found.");

            PgpObjectFactory plainFact = null;

            using (Stream clear = pbe.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                }

                message = of.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                Stream unc = ld.GetInputStream();
                Streams.PipeAll(unc, outputStream);
            }
            else if (message is PgpOnePassSignatureList)
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            else
                throw new PgpException("Message is not a simple encrypted file.");
        }

        #endregion Decrypt

        #region Private helpers

        /*
        * A simple routine that opens a key ring file and loads the first available key suitable for encryption.
        */
        private PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            // iterate through the key rings.
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /*
        * Search a secret key ring collection for a secret key corresponding to keyId if it exists.
        */
        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public void Dispose()
        {
        }

        #endregion Private helpers
    }

}