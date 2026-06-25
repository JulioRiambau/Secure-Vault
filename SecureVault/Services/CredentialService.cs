using Microsoft.EntityFrameworkCore;
using SecureVault.Data;
using SecureVault.Data.Models;

namespace SecureVault.Services;

public class CredentialService
{
    private readonly SecureVaultDbContext _context;
    private readonly EncryptionService _encryptionService;
    private readonly ILogger<CredentialService> _logger;

    public CredentialService(
        SecureVaultDbContext context,
        EncryptionService encryptionService,
        ILogger<CredentialService> logger)
    {
        _context = context;
        _encryptionService = encryptionService;
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
            var credential = new StoredCredential
            {
                UserId = userId,
                ServiceName = serviceName,
                Username = username,
                EncryptedPassword = _encryptionService.Encrypt(password),
                Comment = comment,
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

            credential.ServiceName = serviceName;
            credential.Username = username;

            if (!string.IsNullOrEmpty(password))
            {
                credential.EncryptedPassword = _encryptionService.Encrypt(password);
            }

            credential.Comment = comment;
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
