using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureVault.Components;
using SecureVault.Data;
using SecureVault.Data.Models;
using SecureVault.Services;
using Serilog;

namespace SecureVault
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateBootstrapLogger();

            try
            {
                var builder = WebApplication.CreateBuilder(args);

                builder.Host.UseSerilog((context, services, configuration) => configuration
                    .ReadFrom.Configuration(context.Configuration)
                    .ReadFrom.Services(services)
                    .Enrich.FromLogContext());

                // Add services to the container.
                builder.Services.AddRazorComponents()
                    .AddInteractiveServerComponents();

                // Add DbContext
                builder.Services.AddDbContext<SecureVaultDbContext>(options =>
                    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

                // Add Identity
                builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = false;
                    options.Password.RequireDigit = true;
                    options.Password.RequireLowercase = true;
                    options.Password.RequireUppercase = true;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequiredLength = 6;
                })
                .AddEntityFrameworkStores<SecureVaultDbContext>()
                .AddDefaultTokenProviders();

                // Add custom services
                builder.Services.AddScoped<EncryptionService>();
                builder.Services.AddScoped<CredentialService>();

                // Add authentication state
                builder.Services.AddCascadingAuthenticationState();

                var app = builder.Build();

                app.UseSerilogRequestLogging();
                app.UseExceptionHandler("/Error");

                // Configure the HTTP request pipeline.
                if (!app.Environment.IsDevelopment())
                {
                    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                    app.UseHsts();
                }

                app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
                app.UseHttpsRedirection();

                app.UseAuthentication();
                app.UseAuthorization();

                app.UseAntiforgery();

                app.MapPost("/logout", async (SignInManager<ApplicationUser> signInManager) =>
                {
                    await signInManager.SignOutAsync();
                    return Results.Redirect("/");
                });

                app.MapStaticAssets();
                app.MapRazorComponents<App>()
                    .AddInteractiveServerRenderMode();

                app.Run();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Application terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }
    }
}
