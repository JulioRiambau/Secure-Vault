using Microsoft.AspNetCore.Identity;

namespace SecureVault.Data.Models;

public class ApplicationUser : IdentityUser
{
    public ICollection<StoredCredential> StoredCredentials { get; set; } = new List<StoredCredential>();
}
