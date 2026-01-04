🔐 Password Manager (C# Console App)

A simple console-based password manager built in C# (.NET 10).
Users can create an account, log in, and store app passwords in a locally encrypted vault.

✨ Features

👤 Create Account (Username + Password + Master Password)

🔑 Login System

🗄️ Encrypted Vault

✅ View saved app passwords

➕ Add new app passwords (App Name + Password)

❌ Delete saved passwords (with confirmation)

👀 Main page shows which user is logged in

🔒 Security

Uses AES-GCM encryption to protect saved data

Uses PBKDF2 (SHA256) to derive the key from the Master Password

Vault cannot be decrypted without the correct Master Password

📁 Local Storage

Data is saved in:
📌 AppData\Roaming\PasswordManagerApp\

Files:

account.dat → encrypted login account info

vault.dat → encrypted saved app passwords

🚀 Run the App
dotnet run

✅ Notes

This project is designed for learning and portfolio purposes and demonstrates:

file handling

encryption

menu-driven console design

basic CRUD operations (Add / View / Delete)
