# SafeVaultWebApp - Secure Web Application

## Overview
SafeVaultWebApp is a secure web application designed to manage sensitive data with built-in protection against SQL Injection and XSS (Cross-Site Scripting) attacks.

## Project Structure
```
SafeVaultWebApp/
├── SafeVaultWebApp.Web/
│   ├── .config/
│   │   └── dotnet-tools.json
│   ├── Controllers/
│   │   ├── AdminController.cs
│   │   ├── HomeController.cs
│   │   ├── UserAccountController.cs
│   │   └── UserRoleController.cs
│   ├── Migrations/
│   ├── Models/
│   │   ├── ApplicationDbContext.cs
│   │   ├── LoginViewModel.cs
│   │   └── RegisterViewModel.cs
│   ├── Views/
│   │   ├── Admin/
│   │   │   └── Dashboard.cshtml
│   │   ├── Home/
│   │   │   └── Index.cshtml
│   │   ├── Shared/
│   │   │   ├── _Layout.cshtml
│   │   │   └── _ValidationScriptsPartial.cshtml
│   │   ├── UserAccount/
│   │   │   ├── Login.cshtml
│   │   │   └── Register.cshtml
│   │   └── _ViewImport.cshtml
│   ├── wwwroot/
│   │   ├── css/
│   │   └── js/
│   └── SafeVaultWebApp.Web.csproj
├── SafeVaultWebApp.Tests/
│   ├── Controllers/
│   │   └── UserAccountControllerTests.cs
│   └── SafeVaultWebApp.Tests.csproj
└── SafeVaultWebApp.sln
```

## DB Migrations

To create migration files, execute the following command:
```
dotnet tool run dotnet-ef migrations add <FileName>
```

To un-do the  created migration, execute this command:
```
dotnet tool run dotnet-ef migrations remove
```

To update the database, execute the following command:
```
dotnet tool run dotnet-ef database update
```

## Seeder Setup and Usage

This project includes a `Seeder` class that initializes essential roles and accounts for the application. It ensures that:
- Required roles (`Admin`, `User`) are created
- A default admin account is seeded
- Environment variables are used for secure password handling

### Location

The seeder logic is located in:
```
SafeVaultWebApp.Web/Services/Seeder.cs
```

### Usage

On application startup, the Seeder method for roles and admin seeds are invoked.
These are called from Program.cs inside the scoped service block.

### Environment Variables

To avoid hardcoding sensitive credentials, the seeder reads the following credentials from environment variables for creating the admin account:
- `ADMIN_EMAIL` — admin's email address
- `ADMIN_PASSWORD` — admin's password

Set these in your local `.env` file or deployment environment:
```
ADMIN_EMAIL=admin@safevault.com
ADMIN_PASSWORD=YourSecureAdminPassword!
```

## Testing
Unit tests are located in `SafeVaultWebApp.Tests/`.


To run tests:
```
dotnet test
```

Test coverage includes:
- User registration and login
- Role assignment and redirection
- Input sanitization
- Seeder logic

Integration tests are planned (see [Next Steps](#next-steps)).


## Next Steps

- [ ] Add integration tests using `WebApplicationFactory` and in-memory test server