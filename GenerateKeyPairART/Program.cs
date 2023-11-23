using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
class Program
{
    static void Main()
    {
        try
        {

            var testData = "test";
            var privateKeyPath = @"C:/Keys/ec.key";
            var publicKeyPath = @"C:/Keys/ec.pub";


            AsymmetricCipherKeyPair keyPair = GenerateKeyPair();
            WritePrivateKey(privateKeyPath, keyPair.Private);
            WritePublicKey(publicKeyPath, keyPair.Public);


            var encryptionAlgorithm = "SHA-256withECDSA";
            AsymmetricCipherKeyPair privateKey = ReadAsymmetricKeyPair(privateKeyPath);
            AsymmetricKeyParameter publicKey = ReadPublicKey(publicKeyPath);

            // Data to be signed
            byte[] data = Encoding.UTF8.GetBytes(testData);

            // Sign the data using the private key
            ISigner signer = SignerUtilities.GetSigner(encryptionAlgorithm);
            signer.Init(true, privateKey.Private);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] signature = signer.GenerateSignature();
            var sign = Convert.ToBase64String(signature);

            Console.WriteLine(sign);
            // Verify the signature using the public key
            ISigner verifier = SignerUtilities.GetSigner(encryptionAlgorithm);
            verifier.Init(false, publicKey);
            verifier.BlockUpdate(data, 0, data.Length);

            bool isVerified = verifier.VerifySignature(signature);
            Console.WriteLine("Signature verified: " + isVerified);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
        Console.ReadKey();
    }
    // Helper method to read an AsymmetricCipherKeyPair from a PEM file
    private static AsymmetricCipherKeyPair ReadAsymmetricKeyPair(string filePath)
    {
        using (TextReader reader = File.OpenText(filePath))
        {
            PemReader pemReader = new PemReader(reader);
            return (AsymmetricCipherKeyPair)pemReader.ReadObject();
        }
    }
    // Helper method to read a public key from a PEM file
    private static AsymmetricKeyParameter ReadPublicKey(string filePath)
    {
        using (TextReader reader = File.OpenText(filePath))
        {
            PemReader pemReader = new PemReader(reader);
            return (AsymmetricKeyParameter)pemReader.ReadObject();
        }
    }
    private static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var generator = new ECKeyPairGenerator("ECDSA");
        var keyGenParam = new KeyGenerationParameters(new SecureRandom(), 256); // 256-bit key size
        generator.Init(keyGenParam);
        return generator.GenerateKeyPair();
    }

    private static void WritePrivateKey(string filePath, AsymmetricKeyParameter privateKey)
    {
        using (TextWriter textWriter = new StreamWriter(filePath))
        {
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(privateKey);
            pemWriter.Writer.Flush();
        }
    }

    private static void WritePublicKey(string filePath, AsymmetricKeyParameter publicKey)
    {
        using (TextWriter textWriter = new StreamWriter(filePath))
        {
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();
        }
    }
}