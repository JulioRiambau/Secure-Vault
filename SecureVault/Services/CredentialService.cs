using Microsoft.EntityFrameworkCore;
using SecureVault.Data;
using SecureVault.Data.Models;

namespace SecureVault.Services;

public class CredentialService
{
    private readonly SecureVaultDbContext _context;
    private readonly EncryptionService _encryptionService;
    private readonly InputSanitizationService _sanitizationService;
    private readonly ILogger<CredentialService> _logger;

    public CredentialService(
        SecureVaultDbContext context,
        EncryptionService encryptionService,
        InputSanitizationService sanitizationService,
        ILogger<CredentialService> logger)
    {
        _context = context;
        _encryptionService = encryptionService;
        _sanitizationService = sanitizationService;
        _logger = logger;
    }

    public async Task<List<StoredCredential>> GetUserCredentialsAsync(string userId)
    {
        try
        {
            return await _context.StoredCredentials
                .Where(c => c.UserId == userId)
                .OrderByDescending(c => c.UpdatedAt)
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve credentials for user {UserId}", userId);
            throw;
        }
    }

    public async Task<StoredCredential?> GetCredentialByIdAsync(int id, string userId)
    {
        try
        {
            return await _context.StoredCredentials
                .FirstOrDefaultAsync(c => c.Id == id && c.UserId == userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve credential {CredentialId} for user {UserId}", id, userId);
            throw;
        }
    }

    public async Task<StoredCredential> CreateCredentialAsync(string userId, string serviceName,
        string username, string password, string? comment)
    {
        try
        {
            // Sanitize inputs to prevent XSS and injection attacks
            var sanitizedServiceName = _sanitizationService.SanitizeAndValidate(serviceName);
            var sanitizedUsername = _sanitizationService.SanitizeAndValidate(username);
            var sanitizedPassword = _sanitizationService.Trim(password); // Don't HTML encode passwords
            var sanitizedComment = string.IsNullOrEmpty(comment) ? null : _sanitizationService.SanitizeAndValidate(comment);

            var credential = new StoredCredential
            {
                UserId = userId,
                ServiceName = sanitizedServiceName,
                Username = sanitizedUsername,
                EncryptedPassword = _encryptionService.Encrypt(sanitizedPassword),
                Comment = sanitizedComment,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.StoredCredentials.Add(credential);
            await _context.SaveChangesAsync();

            return credential;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create credential for user {UserId}", userId);
            throw;
        }
    }

    public async Task<bool> UpdateCredentialAsync(int id, string userId, string serviceName,
        string username, string? password, string? comment)
    {
        try
        {
            var credential = await GetCredentialByIdAsync(id, userId);
            if (credential == null)
                return false;

            // Sanitize inputs to prevent XSS and injection attacks
            credential.ServiceName = _sanitizationService.SanitizeAndValidate(serviceName);
            credential.Username = _sanitizationService.SanitizeAndValidate(username);

            if (!string.IsNullOrEmpty(password))
            {
                var sanitizedPassword = _sanitizationService.Trim(password); // Don't HTML encode passwords
                credential.EncryptedPassword = _encryptionService.Encrypt(sanitizedPassword);
            }

            credential.Comment = string.IsNullOrEmpty(comment) ? null : _sanitizationService.SanitizeAndValidate(comment);
            credential.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update credential {CredentialId} for user {UserId}", id, userId);
            throw;
        }
    }

    public async Task<bool> DeleteCredentialAsync(int id, string userId)
    {
        try
        {
            var credential = await GetCredentialByIdAsync(id, userId);
            if (credential == null)
                return false;

            _context.StoredCredentials.Remove(credential);
            await _context.SaveChangesAsync();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete credential {CredentialId} for user {UserId}", id, userId);
            throw;
        }
    }

    public string DecryptPassword(string encryptedPassword)
    {
        try
        {
            return _encryptionService.Decrypt(encryptedPassword);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt credential password");
            throw;
        }
    }
}
