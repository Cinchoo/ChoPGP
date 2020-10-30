using Cinchoo.PGP;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [ClassInitialize()]
        public static void initialize(TestContext testContext)
        {
            if (!File.Exists("SampleData.txt"))
                File.Create("SampleData.txt").Close();
            using (FileStream fs = File.OpenWrite("SampleData.txt"))
            {
                string data = "hola";
                byte[] information = new UTF8Encoding(true).GetBytes(data);
                fs.Write(information, 0, information.Length);
            }
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
                pgp.GenerateKey("Sample_Pub.asc", "Sample_Pri.asc", "mark@gmail.com", "Test123");
            Console.WriteLine("PGP KeyPair generated.");
        }
        [ClassCleanup()]
        public static void cleanup()
        {
            if (File.Exists("SampleData.txt"))
                File.Delete("SampleData.txt");
            if (File.Exists("Sample_Pub.asc"))
                File.Delete("Sample_Pub.asc");
            if (File.Exists("Sample_Pri.asc"))
                File.Delete("Sample_Pri.asc");
            if (File.Exists("SampleData.OUT"))
                File.Delete("SampleData.OUT");
            if (File.Exists("SampleData.PGP"))
                File.Delete("SampleData.PGP");
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
            MemoryStream a = EncryptString("hello");
            string message = DecryptString(a, "Test123");
            Assert.AreEqual("hello", message);
        }
        private MemoryStream EncryptString(string text)
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                MemoryStream a = new System.IO.MemoryStream();

                byte[] byteArray = Encoding.UTF8.GetBytes(text);
                MemoryStream stream = new MemoryStream(byteArray);

                pgp.Encrypt(stream, a, "Sample_Pub.asc", true, false);
                return a;
            }

        }

        private string DecryptString(MemoryStream text, string pass)
        {

            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                using (MemoryStream a = new System.IO.MemoryStream())
                {
                    byte[] r = pgp.Decrypt(text.ToArray(), File.OpenRead("Sample_Pri.asc"), pass);
                    MemoryStream ms = new MemoryStream(r);
                    StreamReader reader = new StreamReader(ms);
                    return reader.ReadToEnd();

                }
            }
        }

        [TestMethod]
        [Priority(10)]
        public void EncryptDecriptNSignStringInMemory()
        {
            MemoryStream a = EncryptNSignInMemory("hello");
            string message = DecryptNVerifyInMemory(a, "Test123");
            Assert.AreEqual("hello", message);
        }

        private MemoryStream EncryptNSignInMemory(string text)
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                MemoryStream a = new System.IO.MemoryStream();

                byte[] byteArray = Encoding.UTF8.GetBytes(text);
                MemoryStream stream = new MemoryStream(byteArray);
                pgp.EncryptAndSign(stream, a, "Sample_Pub.asc", "Sample_Pri.asc", "Test123", true, false);
                return a;
                   
            }
        }

        private string DecryptNVerifyInMemory(MemoryStream text, string pass)
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
            {
                using (MemoryStream a = new System.IO.MemoryStream())
                {
                    Stream message;
                    message = pgp.DecryptAndVerifyInMemory(text, a, "Sample_Pub.asc", "Sample_Pri.asc", pass);
                    MemoryStream ms = new MemoryStream(); ;
                    message.CopyTo(ms);
                    ms = new MemoryStream(a.ToArray());
                    StreamReader reader = new StreamReader(ms);
                    return reader.ReadToEnd();
                    
                }

            }
        }


    }
}

