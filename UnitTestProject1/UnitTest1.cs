using System;
using System.IO;
using System.Text;
using Cinchoo.PGP;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
        }

        [TestMethod]
        [Priority(0)]
        public void TESTGenerateKeyPair()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
                pgp.GenerateKey("Sample_Pub.asc", "Sample_Pri.asc", "mark@gmail.com", "Test123");

            Console.WriteLine("PGP KeyPair generated.");
        }
        [TestMethod]
        [Priority(1)]
        public void EncryptFile()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                pgp.EncryptFile("SampleData.txt", "SampleData.PGP", "Sample_Pub.asc", true, false);
                Console.WriteLine("PGP Encryption done.");
            }
        }
        [TestMethod]
        [Priority(2)]
        public void DecryptFile()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                pgp.DecryptFile("SampleData.PGP", "SampleData.OUT", "Sample_Pri.asc", "Test123");
                Console.WriteLine("PGP Decryption done.");
            }
        }
        [TestMethod]
        [Priority(3)]
        public void Encrypt()
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
        [TestMethod]
        [Priority(4)]
        public void Decrypt()
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
        [TestMethod]
        [Priority(5)]
        public void EncryptFileNSign()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                //pgp.CompressionAlgorithm = ChoCompressionAlgorithm.Zip;
                pgp.EncryptFileAndSign("SampleData.txt", "SampleData.PGP", "Sample_Pub.asc", "Sample_Pri.asc", "Test123", true, false);
                Console.WriteLine("PGP Encryption done.");
            }
        }
        [Priority(6)]
        public void DecryptFileNVerify()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                pgp.DecryptFileAndVerify("SampleData.PGP", "SampleData.OUT", "Sample_Pub.asc", "Sample_Pri.asc", "Test123");
                Console.WriteLine("PGP Decryption done.");
            }
        }
        [TestMethod]
        [Priority(7)]
        public void EncryptNSign()
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
        [TestMethod]
        [Priority(8)]
        public void DecryptNVerify()
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

        [TestMethod]
        [Priority(9)]
        public void EncryptDecriptString()
        {
            Stream a = EncryptString("hello");
            string message = DecryptString(a, "Test123");
            Assert.AreEqual("hello", message);
        }
        private Stream EncryptString(string text)
        {
            
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                //    pgp.EncryptFile("SampleData.txt", "SampleData.PGP", "Pub.asc", true, false);
                //    pgp.DecryptFile("SampleData.PGP", "SampleData.OUT", "Pri.asc", "Test123");
                MemoryStream a = new System.IO.MemoryStream();
                
                    byte[] byteArray = Encoding.UTF8.GetBytes(text);
                    Stream stream = new MemoryStream(byteArray);
                    
                        pgp.Encrypt(stream, a, "Sample_Pub.asc", true, false);
                        return a;
                    
                

                

            }
            
        }

        private string DecryptString(Stream text, string pass)
        {

            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {

                    using (MemoryStream a = new System.IO.MemoryStream())
                    {

                        pgp.Decrypt(text, a, "Sample_Pri.asc", "Test123");
                        StreamReader reader = new StreamReader(a);
                        return reader.ReadToEnd();
                        
                    }
                
                

                

            }
        }
    }
}

