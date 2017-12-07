# Cinchoo PGP

PGP wrapper library for .NET 

Simple, intutive PGP wrapper library for .NET. Extremely clean, flexible, and easy to use. 

## Install

To install Cinchoo PGP, run the following command in the Package Manager Console

    PM> Install-Package ChoPGP

Add namespace to the program

``` csharp
    using ChoPGP;
```
# How to use

To PGP encrypt a file

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.EncryptFile("SampleData.txt", "SampleData.PGP", "Pub.asc", true, false);
    }
```
To PGP encrypt and Sign a file

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.EncryptFileNSign("SampleData.txt", "SampleData.PGP", "Pub.asc", "Pri.asc", "Test123", true, false);
    }
```
To PGP decrypt a file

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.DecryptFile("SampleData.PGP", "SampleData.OUT", "Pri.asc", "Test123");
    }
```
To PGP decrypt and Verify a file

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.DecryptFileNVerify("SampleData.PGP", "SampleData.OUT", "Pub.asc", "Pri.asc", "Test123");
    }
```
Generate Public/Private Keyring

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
        pgp.GenerateKey("pub.asc", "pri.asc", "mark@gmail.com", "Test123");
```
