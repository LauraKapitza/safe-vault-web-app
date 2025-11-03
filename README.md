# SafeVaultWebApp - Secure Web Application

## 🔒 Overview
SafeVaultWebApp is a secure web application designed to manage sensitive data with built-in protection against SQL Injection and XSS (Cross-Site Scripting) attacks.

## 📁 Project Structure
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