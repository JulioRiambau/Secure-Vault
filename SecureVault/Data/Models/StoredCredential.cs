using System.ComponentModel.DataAnnotations;

namespace SecureVault.Data.Models;

public class StoredCredential
{
    public int Id { get; set; }

    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string ServiceName { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string EncryptedPassword { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Comment { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public ApplicationUser User { get; set; } = null!;
}
