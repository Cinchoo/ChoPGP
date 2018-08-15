using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Cinchoo.PGP
{
    public enum ChoPGPFileType { Binary, Text, UTF8 }
    public enum ChoCompressionAlgorithm
    {
        Uncompressed = 0,
        Zip = 1,
        ZLib = 2,
        BZip2 = 3
    }
    public enum ChoSymmetricKeyAlgorithm
    {
        Null = 0,
        Idea = 1,
        TripleDes = 2,
        Cast5 = 3,
        Blowfish = 4,
        Safer = 5,
        Des = 6,
        Aes128 = 7,
        Aes192 = 8,
        Aes256 = 9,
        Twofish = 10,
        Camellia128 = 11,
        Camellia192 = 12,
        Camellia256 = 13
    }
    public enum ChoPublicKeyAlgorithm
    {
        RsaGeneral = 1,
        RsaEncrypt = 2,
        RsaSign = 3,
        ElGamalEncrypt = 16,
        Dsa = 17,
        EC = 18,
        ECDH = 18,
        ECDsa = 19,
        ElGamalGeneral = 20,
        DiffieHellman = 21,
        Experimental_1 = 100,
        Experimental_2 = 101,
        Experimental_3 = 102,
        Experimental_4 = 103,
        Experimental_5 = 104,
        Experimental_6 = 105,
        Experimental_7 = 106,
        Experimental_8 = 107,
        Experimental_9 = 108,
        Experimental_10 = 109,
        Experimental_11 = 110
    }

    public class ChoPGPEncryptDecrypt : IDisposable
    {
        public static readonly ChoPGPEncryptDecrypt Instance = new ChoPGPEncryptDecrypt();

        private const int BufferSize = 0x10000;

        public ChoCompressionAlgorithm CompressionAlgorithm
        {
            get;
            set;
        }

        public ChoSymmetricKeyAlgorithm SymmetricKeyAlgorithm
        {
            get;
            set;
        }

        public int PgpSignatureType
        {
            get;
            set;
        }

        public ChoPublicKeyAlgorithm PublicKeyAlgorithm
        {
            get;
            set;
        }
        public ChoPGPFileType FileType
        {
            get;
            set;
        }

        #region Constructor

        public ChoPGPEncryptDecrypt()
        {
            CompressionAlgorithm = ChoCompressionAlgorithm.Uncompressed;
            SymmetricKeyAlgorithm = ChoSymmetricKeyAlgorithm.TripleDes;
            PgpSignatureType = PgpSignature.DefaultCertification;
            PublicKeyAlgorithm = ChoPublicKeyAlgorithm.RsaGeneral;
            FileType = ChoPGPFileType.Binary;
        }

		#endregion Constructor

		#region EncryptFile

		public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath,
			bool armor = true, bool withIntegrityCheck = true)
		{
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, publicKeyFilePath, armor, withIntegrityCheck));
		}

		/// <summary>
		/// Stream-based encryption, which relies on a local file for input source
		/// </summary>
		/// <param name="input">source to encrypt (local file)</param>
		/// <param name="publicKey">the public key</param>
		/// <param name="output">where to save the encrypted data</param>
		public void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyFilePath,
			bool armor = true, bool withIntegrityCheck = true)
		{
			if (String.IsNullOrEmpty(inputFilePath))
				throw new ArgumentException(nameof(inputFilePath));
			if (String.IsNullOrEmpty(outputFilePath))
				throw new ArgumentException(nameof(outputFilePath));
			if (String.IsNullOrEmpty(publicKeyFilePath))
				throw new ArgumentException(nameof(publicKeyFilePath));

			if (!File.Exists(inputFilePath))
				throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));
			if (!File.Exists(publicKeyFilePath))
				throw new FileNotFoundException(String.Format("Public Key file [{0}] does not exist.", publicKeyFilePath));

			using (Stream pkStream = File.OpenRead(publicKeyFilePath))
			{
				using (Stream outputStream = File.Create(outputFilePath))
				{
					using (Stream inputStream = File.OpenRead(inputFilePath))
						Encrypt(inputStream, outputStream, pkStream, armor, withIntegrityCheck);
				}
			}
		}

		#endregion EncryptFile

		#region Encrypt

		public async Task EncryptAsync(Stream inputStream, Stream outputStream, string publicKeyFilePath,
			bool armor = true, bool withIntegrityCheck = true)
		{
			await Task.Run(() => Encrypt(inputStream, outputStream, File.OpenRead(publicKeyFilePath), armor, withIntegrityCheck));
		}

		public async Task EncryptAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream,
			bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => Encrypt(inputStream, outputStream, publicKeyStream, armor, withIntegrityCheck));
        }

		public void Encrypt(Stream inputStream, Stream outputStream, string publicKeyFilePath,
			bool armor = true, bool withIntegrityCheck = true)
		{
			Encrypt(inputStream, outputStream, File.OpenRead(publicKeyFilePath),
				armor, withIntegrityCheck);
		}

		/// <summary>
		/// PGP Encrypt the file.
		/// </summary>
		/// <param name="inputFilePath"></param>
		/// <param name="outputFilePath"></param>
		/// <param name="publicKeyFilePath"></param>
		/// <param name="armor"></param>
		/// <param name="withIntegrityCheck"></param>
		public void Encrypt(Stream inputStream, Stream outputStream, Stream publicKeyStream,
			bool armor = true, bool withIntegrityCheck = true)
		{
			if (inputStream == null)
				throw new ArgumentException(nameof(inputStream));
			if (outputStream == null)
				throw new ArgumentException(nameof(outputStream));
			if (publicKeyStream == null)
				throw new ArgumentException(nameof(publicKeyStream));

			Stream pkStream = publicKeyStream;

			using (MemoryStream @out = new MemoryStream())
			{
				if (CompressionAlgorithm != ChoCompressionAlgorithm.Uncompressed)
				{
					PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)CompressionAlgorithm);
					ChoPGPUtility.WriteStreamToLiteralData(comData.Open(@out), FileTypeToChar(), inputStream, Path.GetFileName(inputStream));
					comData.Close();
				}
				else
					ChoPGPUtility.WriteStreamToLiteralData(@out, FileTypeToChar(), inputStream, Path.GetFileName(inputStream));

				PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
				pk.AddMethod(ReadPublicKey(pkStream));

				byte[] bytes = @out.ToArray();

				if (armor)
				{
					using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
					{
						using (Stream armoredOutStream = pk.Open(armoredStream, bytes.Length))
						{
							armoredOutStream.Write(bytes, 0, bytes.Length);
						}
					}
				}
				else
				{
					using (Stream plainStream = pk.Open(outputStream, bytes.Length))
					{
						plainStream.Write(bytes, 0, bytes.Length);
					}
				}
			}
		}

		#endregion Encrypt

		#region EncryptFile and Sign

		public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath,
			string passPhrase, bool armor = true, bool withIntegrityCheck = true)
		{
			await Task.Run(() => EncryptFileAndSign(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passPhrase, armor, withIntegrityCheck));
		}

		public void EncryptFileAndSign(string inputFilePath, string outputFilePath, string publicKeyFilePath,
			string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
		{
			if (String.IsNullOrEmpty(inputFilePath))
				throw new ArgumentException(nameof(inputFilePath));
			if (String.IsNullOrEmpty(outputFilePath))
				throw new ArgumentException(nameof(outputFilePath));
			if (String.IsNullOrEmpty(publicKeyFilePath))
				throw new ArgumentException(nameof(publicKeyFilePath));
			if (String.IsNullOrEmpty(privateKeyFilePath))
				throw new ArgumentException(nameof(privateKeyFilePath));
			if (passPhrase == null)
				passPhrase = String.Empty;

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
						OutputEncrypted(inputFilePath, armoredOutputStream, encryptionKeys, withIntegrityCheck);
					}
				}
				else
					OutputEncrypted(inputFilePath, outputStream, encryptionKeys, withIntegrityCheck);
			}
		}

		private void OutputEncrypted(string inputFilePath, Stream outputStream, ChoPGPEncryptionKeys encryptionKeys, bool withIntegrityCheck)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, encryptionKeys, withIntegrityCheck))
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
							inputFileStream.Dispose();
						}
					}
				}
			}
		}
		#endregion EncryptFile and Sign

		#region Encrypt and Sign

		public async Task EncryptAndSignAsync(Stream inputStream, Stream outputStream, string publicKeyFilePath, string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
		{
			await Task.Run(() => EncryptAndSignAsync(inputStream, outputStream, File.OpenRead(publicKeyFilePath),
				File.OpenRead(privateKeyFilePath), passPhrase, armor, withIntegrityCheck));
		}

		public async Task EncryptAndSignAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream, 
			Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptAndSignAsync(inputStream, outputStream, publicKeyStream,
				privateKeyStream, passPhrase, armor, withIntegrityCheck));
        }

		public void EncryptAndSign(Stream inputStream, Stream outputStream, string publicKeyFilePath, string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
		{
			EncryptAndSign(inputStream, outputStream, File.OpenRead(publicKeyFilePath), File.OpenRead(privateKeyFilePath), passPhrase, armor, withIntegrityCheck);
		}

		/// <summary>
		/// Encrypt and sign the file pointed to by unencryptedFileInfo and
		/// </summary>
		/// <param name="inputFilePath"></param>
		/// <param name="outputFilePath"></param>
		/// <param name="publicKeyFilePath"></param>
		/// <param name="privateKeyFilePath"></param>
		/// <param name="passPhrase"></param>
		/// <param name="armor"></param>
		public void EncryptAndSign(Stream inputStream, Stream outputStream, Stream publicKeyStream,
			Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
		{
			if (inputStream == null)
				throw new ArgumentException(nameof(inputStream));
			if (outputStream == null)
				throw new ArgumentException(nameof(outputStream));
			if (publicKeyStream == null)
				throw new ArgumentException(nameof(publicKeyStream));
			if (privateKeyStream == null)
				throw new ArgumentException(nameof(privateKeyStream));
			if (passPhrase == null)
				passPhrase = String.Empty;

			ChoPGPEncryptionKeys encryptionKeys = new ChoPGPEncryptionKeys(publicKeyStream, privateKeyStream, passPhrase);

			if (encryptionKeys == null)
				throw new ArgumentNullException("Encryption Key not found.");

			if (armor)
			{
				using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
				{
					OutputEncrypted(inputStream, armoredOutputStream, encryptionKeys, withIntegrityCheck, Path.GetFileName(inputStream));
				}
			}
			else
				OutputEncrypted(inputStream, outputStream, encryptionKeys, withIntegrityCheck, Path.GetFileName(inputStream));
		}

		private void OutputEncrypted(Stream inputStream, Stream outputStream, ChoPGPEncryptionKeys encryptionKeys, bool withIntegrityCheck, string name)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, encryptionKeys, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
					using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
					{
						WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
						inputStream.Dispose();
					}
				}
			}
		}
		private Stream ChainLiteralStreamOut(Stream compressedOut, Stream inputStream, string name)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, inputStream.Length, DateTime.Now);
		}

		private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, Stream inputStream, PgpSignatureGenerator signatureGenerator)
		{
			int length = 0;
			byte[] buf = new byte[BufferSize];
			while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
			{
				literalOut.Write(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}
			signatureGenerator.Generate().Encode(compressedOut);
		}

		private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
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

        private Stream ChainEncryptedOut(Stream outputStream, ChoPGPEncryptionKeys encryptionKeys, bool withIntegrityCheck)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator = new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
            encryptedDataGenerator.AddMethod(encryptionKeys.PublicKey);
            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        private Stream ChainCompressedOut(Stream encryptedOut)
        {
            if (CompressionAlgorithm != ChoCompressionAlgorithm.Uncompressed)
            {
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)CompressionAlgorithm);
                return compressedDataGenerator.Open(encryptedOut);
            }
            else
                return encryptedOut;
        }

        private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
#if NETCOREAPP2_0
			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file.Name, file.Length, DateTime.Now);
#else
			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file);
#endif
		}

		private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, ChoPGPEncryptionKeys encryptionKeys)
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

#region DecryptFile

        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, privateKeyFilePath, passPhrase));
        }

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
                throw new ArgumentException(nameof(inputFilePath));
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException(nameof(outputFilePath));
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException(nameof(privateKeyFilePath));
            if (passPhrase == null)
                passPhrase = String.Empty;

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

#endregion DecryptFile

#region Decrypt

		public async Task DecryptAsync(Stream inputStream, Stream outputStream, string privateKeyFilePath, string passPhrase)
		{
			await Task.Run(() => Decrypt(inputStream, outputStream, File.OpenRead(privateKeyFilePath), passPhrase));
		}

		public async Task DecryptAsync(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
		{
			await Task.Run(() => Decrypt(inputStream, outputStream, privateKeyStream, passPhrase));
		}

		public void Decrypt(Stream inputStream, Stream outputStream, string privateKeyFilePath, string passPhrase)
		{
			Decrypt(inputStream, outputStream, File.OpenRead(privateKeyFilePath), passPhrase);
		}

		/*
        * PGP decrypt a given stream.
        */
		public void Decrypt(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            if (inputStream == null)
                throw new ArgumentException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentException(nameof(outputStream));
            if (privateKeyStream == null)
                throw new ArgumentException(nameof(privateKeyStream));
            if (passPhrase == null)
                passPhrase = String.Empty;

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
            if (message is PgpOnePassSignatureList)
                message = plainFact.NextPgpObject();

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

#region DecryptFileAndVerify

		public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            await Task.Run(() => DecryptFileAndVerify(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passPhrase));
        }

        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException(nameof(inputFilePath));
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException(nameof(outputFilePath));
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException(nameof(publicKeyFilePath));
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException(nameof(privateKeyFilePath));
            if (passPhrase == null)
                passPhrase = String.Empty;

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(String.Format("Public Key File [{0}] not found.", publicKeyFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFilePath));

            ChoPGPEncryptionKeys encryptionKeys = new ChoPGPEncryptionKeys(publicKeyFilePath, privateKeyFilePath, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            using (Stream inputStream = File.OpenRead(inputFilePath))
            {
                PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKeyEncryptedData(inputStream);
                if (publicKeyED.KeyId != encryptionKeys.PublicKey.KeyId)
                    throw new PgpException(String.Format("Failed to verify file."));

                PgpObject message = GetClearCompressedMessage(publicKeyED, encryptionKeys);

                if (message is PgpCompressedData)
                {
                    message = ProcessCompressedMessage(message);
                    PgpLiteralData literalData = (PgpLiteralData)message;
                    using (Stream outputFile = File.Create(outputFilePath))
                    {
                        using (Stream literalDataStream = literalData.GetInputStream())
                        {
                            Streams.PipeAll(literalDataStream, outputFile);
                        }
                    }
                }
                else if (message is PgpLiteralData)
                {
                    PgpLiteralData literalData = (PgpLiteralData)message;
                    using (Stream outputFile = File.Create(outputFilePath))
                    {
                        using (Stream literalDataStream = literalData.GetInputStream())
                        {
                            Streams.PipeAll(literalDataStream, outputFile);
                        }
                    }
                }
                else
                    throw new PgpException("Message is not a simple encrypted file.");
            }

            return;
        }

#endregion DecryptFileAndVerify

#region DecryptAndVerify

		public async Task DecryptAndVerifyAsync(Stream inputStream, Stream outputStream, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
		{
			await Task.Run(() => DecryptAndVerify(inputStream, outputStream, File.OpenRead(publicKeyFilePath), File.OpenRead(privateKeyFilePath), passPhrase));
		}

		public async Task DecryptAndVerifyAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
		{
			await Task.Run(() => DecryptAndVerify(inputStream, outputStream, publicKeyStream, privateKeyStream, passPhrase));
		}

		public void DecryptAndVerify(Stream inputStream, Stream outputStream, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
		{
			DecryptAndVerify(inputStream, outputStream, File.OpenRead(publicKeyFilePath), File.OpenRead(privateKeyFilePath), passPhrase);
		}

		public void DecryptAndVerify(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
		{
			if (inputStream == null)
				throw new ArgumentException(nameof(inputStream));
			if (outputStream == null)
				throw new ArgumentException(nameof(outputStream));
			if (publicKeyStream == null)
				throw new ArgumentException(nameof(publicKeyStream));
			if (privateKeyStream == null)
				throw new ArgumentException(nameof(privateKeyStream));
			if (passPhrase == null)
				passPhrase = String.Empty;

			ChoPGPEncryptionKeys encryptionKeys = new ChoPGPEncryptionKeys(publicKeyStream, privateKeyStream, passPhrase);

			if (encryptionKeys == null)
				throw new ArgumentNullException("Encryption Key not found.");

			PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKeyEncryptedData(inputStream);
			if (publicKeyED.KeyId != encryptionKeys.PublicKey.KeyId)
				throw new PgpException(String.Format("Failed to verify file."));

			PgpObject message = GetClearCompressedMessage(publicKeyED, encryptionKeys);

			if (message is PgpCompressedData)
			{
				message = ProcessCompressedMessage(message);
				PgpLiteralData literalData = (PgpLiteralData)message;
				using (Stream literalDataStream = literalData.GetInputStream())
				{
					Streams.PipeAll(literalDataStream, outputStream);
				}
			}
			else if (message is PgpLiteralData)
			{
				PgpLiteralData literalData = (PgpLiteralData)message;
				using (Stream literalDataStream = literalData.GetInputStream())
				{
					Streams.PipeAll(literalDataStream, outputStream);
				}
			}
			else
				throw new PgpException("Message is not a simple encrypted file.");

			return;
		}

#endregion DecryptAndVerify

#region GenerateKey

		public async Task GenerateKeyAsync(string publicKeyFilePath, string privateKeyFilePath, string username = null, string password = null, int strength = 1024, int certainty = 8)
        {
            await Task.Run(() => GenerateKey(publicKeyFilePath, privateKeyFilePath, username, password, strength, certainty));
        }

        public void GenerateKey(string publicKeyFilePath, string privateKeyFilePath, string username = null, string password = null, int strength = 1024, int certainty = 8)
        {
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");

            using (Stream pubs = File.Open(publicKeyFilePath, FileMode.OpenOrCreate))
            using (Stream pris = File.Open(privateKeyFilePath, FileMode.OpenOrCreate))
                GenerateKey(pubs, pris, username, password, strength, certainty);
        }

        public void GenerateKey(Stream publicKeyStream, Stream privateKeyStream, string username = null, string password = null, int strength = 1024, int certainty = 8, bool armor = true)
        {
            username = username == null ? string.Empty : username;
            password = password == null ? string.Empty : password;

            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), strength, certainty));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            ExportKeyPair(privateKeyStream, publicKeyStream, kp.Public, kp.Private, username, password.ToCharArray(), armor);
        }

#endregion GenerateKey

#region Private helpers

        private char FileTypeToChar()
        {
            if (FileType == ChoPGPFileType.UTF8)
                return PgpLiteralData.Utf8;
            else if (FileType == ChoPGPFileType.Text)
                return PgpLiteralData.Text;
            else
                return PgpLiteralData.Binary;

        }

        private void ExportKeyPair(
                    Stream secretOut,
                    Stream publicOut,
                    AsymmetricKeyParameter publicKey,
                    AsymmetricKeyParameter privateKey,
                    string identity,
                    char[] passPhrase,
                    bool armor)
        {
            if (secretOut == null)
                throw new ArgumentException("secretOut");
            if (publicOut == null)
                throw new ArgumentException("publicOut");

            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignatureType,
                (PublicKeyAlgorithmTag)(int)PublicKeyAlgorithm,
                publicKey,
                privateKey,
                DateTime.Now,
                identity,
                (SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm,
                passPhrase,
                null,
                null,
                new SecureRandom()
                //                ,"BC"
                );

            secretKey.Encode(secretOut);

            secretOut.Close();

            if (armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOut.Close();
        }

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

        private static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(Stream inputStream)
        {
            Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(encodedFile);
            PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKey(encryptedDataList);
            return publicKeyED;
        }
        private static PgpObject ProcessCompressedMessage(PgpObject message)
        {
            PgpCompressedData compressedData = (PgpCompressedData)message;
            Stream compressedDataStream = compressedData.GetDataStream();
            PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedDataStream);
            message = CheckforOnePassSignatureList(message, compressedFactory);
            return message;
        }
        private static PgpObject CheckforOnePassSignatureList(PgpObject message, PgpObjectFactory compressedFactory)
        {
            message = compressedFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
            {
                message = compressedFactory.NextPgpObject();
            }
            return message;
        }
        private PgpObject GetClearCompressedMessage(PgpPublicKeyEncryptedData publicKeyED, ChoPGPEncryptionKeys encryptionKeys)
        {
            PgpObjectFactory clearFactory = GetClearDataStream(encryptionKeys.PrivateKey, publicKeyED);
            PgpObject message = clearFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
                message = clearFactory.NextPgpObject();
            return message;
        }
        private static PgpObjectFactory GetClearDataStream(PgpPrivateKey privateKey, PgpPublicKeyEncryptedData publicKeyED)
        {
            Stream clearStream = publicKeyED.GetDataStream(privateKey);
            PgpObjectFactory clearFactory = new PgpObjectFactory(clearStream);
            return clearFactory;
        }
        private static PgpPublicKeyEncryptedData ExtractPublicKey(PgpEncryptedDataList encryptedDataList)
        {
            PgpPublicKeyEncryptedData publicKeyED = null;
            foreach (PgpPublicKeyEncryptedData privateKeyED in encryptedDataList.GetEncryptedDataObjects())
            {
                if (privateKeyED != null)
                {
                    publicKeyED = privateKeyED;
                    break;
                }
            }
            return publicKeyED;
        }
        private static PgpEncryptedDataList GetEncryptedDataList(Stream encodedFile)
        {
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            PgpEncryptedDataList encryptedDataList;

            if (pgpObject is PgpEncryptedDataList)
            {
                encryptedDataList = (PgpEncryptedDataList)pgpObject;
            }
            else
            {
                encryptedDataList = (PgpEncryptedDataList)factory.NextPgpObject();
            }
            return encryptedDataList;
        }
        public void Dispose()
        {
        }

#endregion Private helpers
    }

}
