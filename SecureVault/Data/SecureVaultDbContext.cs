using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureVault.Data.Models;

namespace SecureVault.Data;

public class SecureVaultDbContext : IdentityDbContext<ApplicationUser>
{
    public SecureVaultDbContext(DbContextOptions<SecureVaultDbContext> options)
        : base(options)
    {
    }

    public DbSet<StoredCredential> StoredCredentials { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<StoredCredential>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.UserId);

            entity.HasOne(e => e.User)
                .WithMany(u => u.StoredCredentials)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("datetime('now')");

            entity.Property(e => e.UpdatedAt)
                .HasDefaultValueSql("datetime('now')");
        });
    }
}
