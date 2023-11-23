using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using Newtonsoft.Json;
using System.IO;
using Org.BouncyCastle.OpenSsl;

namespace SaveKeyPair
{
    internal class Program
    {
        static void Main(string[] args)
        {
            AsymmetricCipherKeyPair keyPair = GenerateKeyPair();

            string keyPrivate = ConvertPrivateKeyToPEM(keyPair.Private);
            Console.WriteLine(keyPrivate);
        }
        private static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var generator = new ECKeyPairGenerator("ECDSA");
            var keyGenParam = new KeyGenerationParameters(new SecureRandom(), 256); // 256-bit key size
            generator.Init(keyGenParam);
            return generator.GenerateKeyPair();
        }
        private static string ConvertPrivateKeyToPEM(AsymmetricKeyParameter privateKey)
        {
            var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(privateKey);
            pemWriter.Writer.Close();

            return stringWriter.ToString();
        }
    }
}
