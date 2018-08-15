using Cinchoo.PGP;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ChoPGP.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            //GenerateKeyPair();
            //EncryptFile();
            //DecryptFile();
            //Console.ReadLine();
            //EncryptFile();
            //DecryptFile();

            //EncryptFileNSign();
            //DecryptFileNVerify();
            EncryptNSign();
            DecryptNVerify();
        }

        private static void GenerateKeyPair()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
                pgp.GenerateKey("pub.asc", "pri.asc", "mark@gmail.com", "Test123");

            Console.WriteLine("PGP KeyPair generated.");
        }

        private static void EncryptFile()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                pgp.EncryptFile("SampleData.txt", "SampleData.PGP", "Sample_Pub.asc", true, false);
                Console.WriteLine("PGP Encryption done.");
            }
        }
        private static void DecryptFile()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                pgp.DecryptFile("SampleData.PGP", "SampleData.OUT", "Sample_Pri.asc", "Test123");
                Console.WriteLine("PGP Decryption done.");
            }
        }

        private static void Encrypt()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                using (Stream input = File.OpenRead("SampleData.txt"))
                {
                    using (Stream output = File.OpenWrite("SampleData.PGP"))
                    {
                        //pgp.CompressionAlgorithm = ChoCompressionAlgorithm.Zip;
                        pgp.Encrypt(input, output, "Sample_Pub.asc", true, false);
                    }
                }
            }
        }
        private static void Decrypt()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                using (Stream input = File.OpenRead("SampleData.PGP"))
                {
                    using (Stream output = File.OpenWrite("SampleData.OUT"))
                    {
                        pgp.Decrypt(input, output, "Sample_Pri.asc", "Test123");
                    }
                }
                Console.WriteLine("PGP Decryption done.");
            }
        }

        private static void EncryptFileNSign()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                //pgp.CompressionAlgorithm = ChoCompressionAlgorithm.Zip;
                pgp.EncryptFileAndSign("SampleData.txt", "SampleData.PGP", "Sample_Pub.asc", "Sample_Pri.asc", "Test123", true, false);
                Console.WriteLine("PGP Encryption done.");
            }
        }

        private static void DecryptFileNVerify()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                pgp.DecryptFileAndVerify("SampleData.PGP", "SampleData.OUT", "Sample_Pub.asc", "Sample_Pri.asc", "Test123");
                Console.WriteLine("PGP Decryption done.");
            }
        }
        private static void EncryptNSign()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                using (Stream input = File.OpenRead("SampleData.txt"))
                {
                    using (Stream output = File.OpenWrite("SampleData.PGP"))
                    {
                        //pgp.CompressionAlgorithm = ChoCompressionAlgorithm.Zip;
                        pgp.EncryptAndSign(input, output, "Sample_Pub.asc", "Sample_Pri.asc", "Test123", true, false);
                    }
                }
            }
            Console.WriteLine("PGP Encryption done.");
        }

        private static void DecryptNVerify()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                using (Stream input = File.OpenRead("SampleData.PGP"))
                {
                    using (Stream output = File.OpenWrite("SampleData.OUT"))
                    {
                        pgp.DecryptAndVerify(input, output, "Sample_Pub.asc", "Sample_Pri.asc", "Test123");
                    }
                }
                Console.WriteLine("PGP Decryption done.");
            }
        }
    }
}
