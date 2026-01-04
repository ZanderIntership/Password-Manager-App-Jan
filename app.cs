using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

class ProgramShow
{
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int Iterations = 100_000;

    static void Main()
    {
        string appFolder = GetAppFolder();
        string accountFile = Path.Combine(appFolder, "account.dat");
        string vaultFile = Path.Combine(appFolder, "vault.dat");

        while (true)
        {
            Console.Clear();
            ShowBanner();

            Console.WriteLine("\n1) Login");
            Console.WriteLine("2) Create Account");
            Console.WriteLine("3) Exit\n");

            Console.Write("Select an option: ");
            string choice = (Console.ReadLine() ?? "").Trim();

            switch (choice)
            {
                case "1":
                    LoginFlow(accountFile, vaultFile);
                    break;

                case "2":
                    CreateAccountFlow(accountFile, appFolder);
                    break;

                case "3":
                    Console.WriteLine("\nGoodbye!");
                    return;

                default:
                    Console.WriteLine("\nInvalid option. Press any key to try again...");
                    Console.ReadKey();
                    break;
            }
        }
    }

    static void CreateAccountFlow(string accountFile, string appFolder)
    {
        Console.Clear();
        ShowBanner();
        Console.WriteLine("\n--- CREATE ACCOUNT ---\n");

        string username = AskNotEmpty("Create Username: ");
        string password = AskNotEmpty("Create Password: ");
        string masterPassword = AskNotEmpty("Set a MASTER password (used to unlock your vault): ");

        SaveAccount(accountFile, username, password, masterPassword);

        Console.WriteLine("\nAccount created and saved locally (encrypted).");
        Console.WriteLine($"Saved in: {appFolder}");

        Console.WriteLine("\nPress any key to return to Login/Sign Up...");
        Console.ReadKey();
    }

    static void LoginFlow(string accountFile, string vaultFile)
    {
        Console.Clear();
        ShowBanner();
        Console.WriteLine("\n--- LOGIN ---\n");

        if (!File.Exists(accountFile))
        {
            Console.WriteLine("No saved account found. Please create an account first.");
            Console.WriteLine("\nPress any key to return...");
            Console.ReadKey();
            return;
        }

        string inputUser = AskNotEmpty("Username: ");
        string inputPass = AskNotEmpty("Password: ");
        string masterPassword = AskNotEmpty("Master Password: ");

        try
        {
            var (savedUser, savedPass) = LoadAccount(accountFile, masterPassword);

            if (inputUser == savedUser && inputPass == savedPass)
            {
                Console.WriteLine("\nLogin successful.");
                Console.ReadKey();

                
                MainMenu(savedUser, vaultFile, masterPassword);
            }
            else
            {
                Console.WriteLine("\nInvalid username or password.");
                Console.WriteLine("\nPress any key to return...");
                Console.ReadKey();
            }
        }
        catch
        {
            Console.WriteLine("\nERROR: Failed to decrypt. Master password is wrong OR file is corrupted.");
            Console.WriteLine("\nPress any key to return...");
            Console.ReadKey();
        }
    }

    static void MainMenu(string loggedInUser, string vaultFile, string masterPassword)
    {
        while (true)
        {
            ShowMainPage(loggedInUser);

            Console.Write("Select an option: ");
            string choice = (Console.ReadLine() ?? "").Trim();

            switch (choice)
            {
                case "1":
                    ViewSavedPasswords(vaultFile, masterPassword);
                    break;

                case "2":
                    AddNewPassword(vaultFile, masterPassword);
                    break;

                case "3":
                    DeletePassword(vaultFile, masterPassword);
                    break;

                case "4":
                    Console.WriteLine("\nLogging out...");
                    Console.ReadKey();
                    Console.Clear();
                    return;

                default:
                    Console.WriteLine("\nInvalid choice. Press any key to try again...");
                    Console.ReadKey();
                    break;
            }
        }
    }

    static void ViewSavedPasswords(string vaultFile, string masterPassword)
    {
        Console.Clear();
        Console.WriteLine("=== SAVED PASSWORDS ===\n");

        var vault = LoadVault(vaultFile, masterPassword);

        if (vault.Count == 0)
        {
            Console.WriteLine("No saved passwords yet.");
        }
        else
        {
            for (int i = 0; i < vault.Count; i++)
            {
                Console.WriteLine($"{i + 1}) {vault[i].AppName}  |  {vault[i].Password}");
            }
        }

        Console.WriteLine("\nPress any key to return...");
        Console.ReadKey();
    }

    static void AddNewPassword(string vaultFile, string masterPassword)
    {
        Console.Clear();
        Console.WriteLine("=== ADD NEW PASSWORD ===\n");

        string appName = AskNotEmpty("App Name: ");
        string appPassword = AskNotEmpty("Password: ");

        var vault = LoadVault(vaultFile, masterPassword);

        
        int index = vault.FindIndex(x => x.AppName.Equals(appName, StringComparison.OrdinalIgnoreCase));

        if (index >= 0)
        {
            Console.WriteLine("\nThis app already exists. Updating password...");
            vault[index].Password = appPassword;
        }
        else
        {
            vault.Add(new VaultEntry { AppName = appName, Password = appPassword });
        }

        SaveVault(vaultFile, vault, masterPassword);

        Console.WriteLine("\nSaved successfully.");
        Console.WriteLine("\nPress any key to return...");
        Console.ReadKey();
    }

    static void DeletePassword(string vaultFile, string masterPassword)
    {
        Console.Clear();
        Console.WriteLine("=== DELETE PASSWORD ===\n");

        var vault = LoadVault(vaultFile, masterPassword);

        if (vault.Count == 0)
        {
            Console.WriteLine("No saved passwords to delete.");
            Console.WriteLine("\nPress any key to return...");
            Console.ReadKey();
            return;
        }

        for (int i = 0; i < vault.Count; i++)
        {
            Console.WriteLine($"{i + 1}) {vault[i].AppName}");
        }

        Console.Write("\nEnter the number of the app to delete: ");
        string input = (Console.ReadLine() ?? "").Trim();

        if (!int.TryParse(input, out int choice) || choice < 1 || choice > vault.Count)
        {
            Console.WriteLine("\nInvalid selection.");
            Console.WriteLine("\nPress any key to return...");
            Console.ReadKey();
            return;
        }

        var selected = vault[choice - 1];

        Console.Write($"\nAre you sure you want to delete '{selected.AppName}'? (Y/N): ");
        string confirm = (Console.ReadLine() ?? "").Trim().ToUpper();

        if (confirm != "Y")
        {
            Console.WriteLine("\nDelete cancelled.");
            Console.WriteLine("\nPress any key to return...");
            Console.ReadKey();
            return;
        }

        vault.RemoveAt(choice - 1);
        SaveVault(vaultFile, vault, masterPassword);

        Console.WriteLine($"\n'{selected.AppName}' deleted successfully.");
        Console.WriteLine("\nPress any key to return...");
        Console.ReadKey();
    }

    class VaultEntry
    {
        public string AppName { get; set; } = "";
        public string Password { get; set; } = "";
    }

    static List<VaultEntry> LoadVault(string vaultFile, string masterPassword)
    {
        if (!File.Exists(vaultFile))
            return new List<VaultEntry>();

        string json = DecryptFromFile(vaultFile, masterPassword);
        return JsonSerializer.Deserialize<List<VaultEntry>>(json) ?? new List<VaultEntry>();
    }

    static void SaveVault(string vaultFile, List<VaultEntry> vault, string masterPassword)
    {
        string json = JsonSerializer.Serialize(vault, new JsonSerializerOptions { WriteIndented = true });
        EncryptToFile(vaultFile, json, masterPassword);
    }

    static void SaveAccount(string filePath, string username, string password, string masterPassword)
    {
        // Store as JSON (username + password) encrypted
        var obj = new { Username = username, Password = password };
        string json = JsonSerializer.Serialize(obj);

        EncryptToFile(filePath, json, masterPassword);
    }

    static (string Username, string Password) LoadAccount(string filePath, string masterPassword)
    {
        string json = DecryptFromFile(filePath, masterPassword);
        var obj = JsonSerializer.Deserialize<Dictionary<string, string>>(json);

        if (obj == null || !obj.ContainsKey("Username") || !obj.ContainsKey("Password"))
            throw new Exception("Account file is invalid.");

        return (obj["Username"], obj["Password"]);
    }



    static void EncryptToFile(string filePath, string plaintext, string masterPassword)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] key = DeriveKey(masterPassword, salt);

        byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] cipherBytes = new byte[plainBytes.Length];
        byte[] tag = new byte[TagSize];

        using (var aes = new AesGcm(key))
        {
            aes.Encrypt(nonce, plainBytes, cipherBytes, tag);
        }

        
        using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        fs.Write(salt, 0, salt.Length);
        fs.Write(nonce, 0, nonce.Length);
        fs.Write(tag, 0, tag.Length);
        fs.Write(cipherBytes, 0, cipherBytes.Length);
    }

    static string DecryptFromFile(string filePath, string masterPassword)
    {
        byte[] all = File.ReadAllBytes(filePath);
        int offset = 0;

        byte[] salt = all[offset..(offset + SaltSize)];
        offset += SaltSize;

        byte[] nonce = all[offset..(offset + NonceSize)];
        offset += NonceSize;

        byte[] tag = all[offset..(offset + TagSize)];
        offset += TagSize;

        byte[] cipherBytes = all[offset..];

        byte[] key = DeriveKey(masterPassword, salt);
        byte[] plainBytes = new byte[cipherBytes.Length];

        using (var aes = new AesGcm(key))
        {
            aes.Decrypt(nonce, cipherBytes, tag, plainBytes);
        }

        return Encoding.UTF8.GetString(plainBytes);
    }

    static byte[] DeriveKey(string masterPassword, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            masterPassword,
            salt,
            Iterations,
            HashAlgorithmName.SHA256
        );

        return pbkdf2.GetBytes(KeySize);
    }

    static string AskNotEmpty(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string input = (Console.ReadLine() ?? "").Trim();

            if (!string.IsNullOrWhiteSpace(input))
                return input;

            Console.WriteLine("Input cannot be empty.");
        }
    }

    static string GetAppFolder()
    {
        string folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PasswordManagerApp"
        );

        Directory.CreateDirectory(folder);
        return folder;
    }

    static void ShowBanner()
    {
        Console.WriteLine(" ____   _    ____ ____ __        _____  ____  ____    __  __    _    _   _    _    ____ _____ ____  ");
        Console.WriteLine("|  _ \\ / \\  / ___/ ___|\\ \\      / / _ \\|  _ \\|  _ \\  |  \\/  |  / \\  | \\ | |  / \\  / ___| ____|  _ \\ ");
        Console.WriteLine("| |_) / _ \\ \\___ \\___ \\ \\ \\ /\\ / / | | | |_) | | | | | |\\/| | / _ \\ |  \\| | / _ \\| |  _|  _| | |_) |");
        Console.WriteLine("|  __/ ___ \\ ___) |__) | \\ V  V /| |_| |  _ <| |_| | | |  | |/ ___ \\| |\\  |/ ___ \\ |_| | |___|  _ < ");
        Console.WriteLine("|_| /_/   \\_\\____/____/   \\_/\\_/  \\___/|_| \\_\\____/  |_|  |_/_/   \\_\\_| \\_/_/   \\_\\____|_____|_| \\_\\");
        Console.WriteLine("=====================================================================================================");
    }

    static void ShowMainPage(string loggedInUser)
    {
        Console.Clear();

        Console.WriteLine(" __  __    _    ___ _   _   ____   _    ____ _____ ");
        Console.WriteLine("|  \\/  |  / \\  |_ _| \\ | | |  _ \\ / \\  / ___| ____|");
        Console.WriteLine("| |\\/| | / _ \\  | ||  \\| | | |_) / _ \\| |  _|  _|  ");
        Console.WriteLine("| |  | |/ ___ \\ | || |\\  | |  __/ ___ \\ |_| | |___ ");
        Console.WriteLine("|_|  |_/_/   \\_\\___|_| \\_| |_| /_/   \\_\\____|_____|");
        Console.WriteLine("====================================================\n");

        Console.WriteLine($"Logged in as: {loggedInUser}\n");

        Console.WriteLine("1) View Saved Passwords");
        Console.WriteLine("2) Add New Password");
        Console.WriteLine("3) Delete Password");
        Console.WriteLine("4) Logout\n");
    }
}
