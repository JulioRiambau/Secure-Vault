using System.Security.Cryptography;
using System.Text;

namespace SecureVault.Services;

public class EncryptionService
{
    private readonly byte[] _key;
    private readonly ILogger<EncryptionService> _logger;

    public EncryptionService(IConfiguration configuration, ILogger<EncryptionService> logger)
    {
        _logger = logger;

        var keyString = configuration["Encryption:Key"]
            ?? throw new InvalidOperationException("Encryption key not configured");
        var keyBytes = Convert.FromBase64String(keyString);
        if (keyBytes.Length != 32)
        {
            throw new InvalidOperationException("Encryption key must be exactly 32 bytes (256 bits)");
        }

        _key = keyBytes;
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        try
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.GenerateIV();

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using var msEncrypt = new MemoryStream();
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plainText);
            }

            var encrypted = msEncrypt.ToArray();
            var result = new byte[aes.IV.Length + encrypted.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(encrypted, 0, result, aes.IV.Length, encrypted.Length);

            return Convert.ToBase64String(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to encrypt sensitive data");
            throw;
        }
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        try
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            using var aes = Aes.Create();
            aes.Key = _key;

            var iv = new byte[aes.IV.Length];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            aes.IV = iv;

            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using var msDecrypt = new MemoryStream(cipher);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);

            return srDecrypt.ReadToEnd();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt sensitive data");
            throw;
        }
    }
}
