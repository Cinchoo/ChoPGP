using Cinchoo.PGP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ChoPGP.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            GenerateKeyPair();
            EncryptFile();
            DecryptFile();
        }

        private static void GenerateKeyPair()
        {
            using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
                pgp.CreateRSAKeyPair("mark@gmail.com", "Test123").SaveToFile("pub.asc", "pri.asc");

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
    }
}
