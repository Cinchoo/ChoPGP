# Cinchoo PGP

PGP wrapper library for .NET 

Simple, intutive PGP wrapper library for .NET. Extremely clean, flexible, and easy to use. 

# How to use

To PGP encrypt a file

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.EncryptFile("SampleData.txt", "SampleData.PGP", "Sample_Pub.asc", true, false);
    }
```

To PGP decrypt a file

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.DecryptFile("SampleData.PGP", "SampleData.OUT", "Sample_Pri.asc", "Test123");
    }
```
Generate Public/Private Keyring

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
        var key = pgp.CreateRSAKeyPair("mark@gmail.com", "Test123");
```
Generate And Save Public/Private Keyring

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
        pgp.CreateRSAKeyPair("mark@gmail.com", "Test123").SaveToFile("pub.asc", "pri.asc");
```
