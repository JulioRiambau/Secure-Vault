# SecureVault - Database Migration Setup

# Run these commands from the workspace root directory (C:\Git\Secure-Vault\)

# Step 1: Create the initial migration
cd SecureVault
dotnet ef migrations add InitialCreate

# Step 2: Apply the migration to create the database
dotnet ef database update

# The database file 'securevault.db' will be created in the SecureVault directory
