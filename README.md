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

## 1. To PGP encrypt a file

``` csharp
public void EncryptFile(string inputFilePath, string outputFilePath, 
           string publicKeyFilePath, bool armor, bool withIntegrityCheck);
           
```
where:

    inputFilePath - Plain data file path to be encrypted
    outputFilePath - Output PGP encrypted file path
    publicKeyFilePath - PGP public key file path
    armor - True, means a binary data representation as an ASCII-only text. Otherwise, false
    withIntegrityCheck - True, to perform integrity packet check on input file. Otherwise, false

#### Sample 

``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.EncryptFile("SampleData.txt", "SampleData.PGP", "Pub.asc", true, false);
    }
```

## 2. To PGP encrypt and Sign a file

``` csharp
public void EncryptFileAndSign(string inputFilePath, string outputFilePath, 
           string publicKeyFilePath, string privateKeyFilePath, string passPhrase, bool armor, bool withIntegrityCheck);
           
```
where:

    inputFilePath - Plain data file path to be encrypted
    outputFilePath - Output PGP encrypted file path
    publicKeyFilePath - PGP public key file path
    privateKeyFilePath - PGP secret key file path
    passPhrase - PGP secret key password
    armor - True, means a binary data representation as an ASCII-only text. Otherwise, false
    withIntegrityCheck - True, to perform integrity packet check on input file. Otherwise, false

#### Sample 
``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.EncryptFileNSign("SampleData.txt", "SampleData.PGP", "Pub.asc", "Pri.asc", "Test123", true, false);
    }
```
## 3. To PGP decrypt a file

``` csharp
public void DecryptFile(string inputFilePath, string outputFilePath, 
           string privateKeyFilePath, string passPhrase);
           
```
where:

    inputFilePath - PGP encrypted data file
    outputFilePath - Output of decrypted file path
    privateKeyFilePath - PGP secret key file path
    passPhrase - PGP secret key password

#### Sample 
``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.DecryptFile("SampleData.PGP", "SampleData.OUT", "Pri.asc", "Test123");
    }
```
## 4. To PGP decrypt and Verify a file

``` csharp
public void DecryptFile(string inputFilePath, string outputFilePath, string publicKeyFilePath,
           string privateKeyFilePath, string passPhrase);
           
```
where:

    inputFilePath - PGP encrypted data file
    outputFilePath - Output of decrypted file path
    publicKeyFilePath - PGP public key file path
    privateKeyFilePath - PGP secret key file path
    passPhrase - PGP secret key password

#### Sample 
``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
    {
        pgp.DecryptFileNVerify("SampleData.PGP", "SampleData.OUT", "Pub.asc", "Pri.asc", "Test123");
    }
```
## 5. Generate Public/Private Keyring

``` csharp
    public void GenerateKey(Stream publicKeyStream, Stream privateKeyStream, 
           string username = null, string password = null, int strength = 1024, int certainty = 8);
           
```
where:

    publicKeyFilePath - File path to store the PGP public key info. Put this key on your website or at the bottom signature of your email messages. Anyone wishing to contact you in private will have your public PGP to send you encrypted messages
    privateKeyFilePath - File path to store the PGP private key info. Save your PGP private key in a file on your computer and keep it as confidential as possible.
    userName - Your email address is recommended for generating your PGP keys. Your email address will be included as public information in your public PGP key, so your public key can be easily imported by any third-party PGP software. If you do not supply your email address, your PGP decryption software may be unable to link your email address to your public PGP key, and therefore unable to automatically encrypt/decrypt email messages. As a result, you will have to manually decrypt messages each time you receive a PGP-encrypted message.
    password - Pick a password to protect your private PGP key. This password offers an extra layer of protection in case someone manages to steal your public PGP key.
    strength - The key strength. Default value is 1024.
    certainty - Certainty for prime evaluation. Bouncy Castle uses this number to generate random number and checks whether or not they are prime numbers using prime test algorithm. Default value is 8.

#### Sample 
``` csharp
    using (ChoPGPEncryptDecrypt pgp = new ChoPGPEncryptDecrypt())
        pgp.GenerateKey("pub.asc", "pri.asc", "mark@gmail.com", "Test123");
```
