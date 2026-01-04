using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class ProgramShow
{
    private const int SaltSize = 16;   // 128-bit
    private const int NonceSize = 12;  // 96-bit (recommended for GCM)
    private const int TagSize = 16;    // 128-bit authentication tag
    private const int KeySize = 32;    // 256-bit key
    private const int Iterations = 100_000;

    static void Main()
    {
        string appFolder = GetAppFolder();
        string accountFile = Path.Combine(appFolder, "account.dat");

        Console.WriteLine(" ____   _    ____ ____ __        _____  ____  ____    __  __    _    _   _    _    ____ _____ ____  ");
        Console.WriteLine("|  _ \\ / \\  / ___/ ___|\\ \\      / / _ \\|  _ \\|  _ \\  |  \\/  |  / \\  | \\ | |  / \\  / ___| ____|  _ \\ ");
        Console.WriteLine("| |_) / _ \\ \\___ \\___ \\ \\ \\ /\\ / / | | | |_) | | | | | |\\/| | / _ \\ |  \\| | / _ \\| |  _|  _| | |_) |");
        Console.WriteLine("|  __/ ___ \\ ___) |__) | \\ V  V /| |_| |  _ <| |_| | | |  | |/ ___ \\| |\\  |/ ___ \\ |_| | |___|  _ < ");
        Console.WriteLine("|_| /_/   \\_\\____/____/   \\_/\\_/  \\___/|_| \\_\\____/  |_|  |_/_/   \\_\\_| \\_/_/   \\_\\____|_____|_| \\_\\");
        Console.WriteLine("=====================================================================================================");

        string haveAnAccount = AskYesNo("Do you have an account? (Y/N): ");

        if (haveAnAccount == "N")
        {
            Console.WriteLine("\n--- CREATE ACCOUNT ---");

            string username = AskNotEmpty("Create Username: ");
            string password = AskNotEmpty("Create Password: ");

            string masterPassword = AskNotEmpty("Set a MASTER password (used to unlock your saved password): ");

            SaveAccount(accountFile, username, password, masterPassword);

            Console.WriteLine("\nAccount created and saved locally (encrypted).");
            Console.WriteLine($"Saved in: {appFolder}");

            PauseAndExit();
            return;
        }
        else
        {
            Console.WriteLine("\n--- LOGIN ---");

            if (!File.Exists(accountFile))
            {
                Console.WriteLine("No saved account found. Please create an account first.");
                PauseAndExit();
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
                    Console.ReadKey(); // pause briefly
                    MainMenu();        // ✅ show main page + loop
                    return;
                }
                else
                {
                    Console.WriteLine("\nInvalid username or password.");
                    PauseAndExit();
                    return;
                }
            }
            catch
            {
                Console.WriteLine("\nERROR: Failed to decrypt. Master password is wrong OR file is corrupted.");
                PauseAndExit();
                return;
            }
        }
    }

    // ==========================
    // MAIN MENU LOOP
    // ==========================

    static void MainMenu()
    {
        while (true)
        {
            ShowMainPage();

            Console.Write("Select an option: ");
            string choice = (Console.ReadLine() ?? "").Trim();

            switch (choice)
            {
                case "1":
                    Console.WriteLine("\n[Placeholder] Viewing saved passwords...");
                    Console.ReadKey();
                    break;

                case "2":
                    Console.WriteLine("\n[Placeholder] Adding new password...");
                    Console.ReadKey();
                    break;

                case "3":
                    Console.WriteLine("\n[Placeholder] Deleting password...");
                    Console.ReadKey();
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

    // ==========================
    // STORAGE: Save / Load
    // ==========================

    static void SaveAccount(string filePath, string username, string password, string masterPassword)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

        byte[] key = DeriveKey(masterPassword, salt);

        byte[] plainBytes = Encoding.UTF8.GetBytes(password);
        byte[] cipherBytes = new byte[plainBytes.Length];
        byte[] tag = new byte[TagSize];

        using (var aes = new AesGcm(key))
        {
            aes.Encrypt(nonce, plainBytes, cipherBytes, tag);
        }

        byte[] userBytes = Encoding.UTF8.GetBytes(username);
        byte[] userLenBytes = BitConverter.GetBytes(userBytes.Length);

        using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        fs.Write(salt, 0, salt.Length);
        fs.Write(nonce, 0, nonce.Length);
        fs.Write(tag, 0, tag.Length);
        fs.Write(userLenBytes, 0, userLenBytes.Length);
        fs.Write(userBytes, 0, userBytes.Length);
        fs.Write(cipherBytes, 0, cipherBytes.Length);
    }

    static (string Username, string Password) LoadAccount(string filePath, string masterPassword)
    {
        byte[] all = File.ReadAllBytes(filePath);

        int offset = 0;

        byte[] salt = all[offset..(offset + SaltSize)];
        offset += SaltSize;

        byte[] nonce = all[offset..(offset + NonceSize)];
        offset += NonceSize;

        byte[] tag = all[offset..(offset + TagSize)];
        offset += TagSize;

        int usernameLength = BitConverter.ToInt32(all, offset);
        offset += 4;

        byte[] userBytes = all[offset..(offset + usernameLength)];
        offset += usernameLength;

        byte[] cipherBytes = all[offset..];

        byte[] key = DeriveKey(masterPassword, salt);
        byte[] plainBytes = new byte[cipherBytes.Length];

        using (var aes = new AesGcm(key))
        {
            aes.Decrypt(nonce, cipherBytes, tag, plainBytes);
        }

        string username = Encoding.UTF8.GetString(userBytes);
        string password = Encoding.UTF8.GetString(plainBytes);

        return (username, password);
    }

    static byte[] DeriveKey(string masterPassword, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password: masterPassword,
            salt: salt,
            iterations: Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256
        );

        return pbkdf2.GetBytes(KeySize);
    }

    // ==========================
    // Helpers: Input and Folder
    // ==========================

    static string GetAppFolder()
    {
        string folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PasswordManagerApp"
        );

        Directory.CreateDirectory(folder);
        return folder;
    }

    static string AskYesNo(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string input = (Console.ReadLine() ?? "").Trim().ToUpper();

            if (input == "Y" || input == "N")
                return input;

            Console.WriteLine("Invalid input. Please type Y or N.");
        }
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

    static void ShowMainPage()
    {
        Console.Clear();

        Console.WriteLine(" __  __    _    ___ _   _   ____   _    ____ _____ ");
        Console.WriteLine("|  \\/  |  / \\  |_ _| \\ | | |  _ \\ / \\  / ___| ____|");
        Console.WriteLine("| |\\/| | / _ \\  | ||  \\| | | |_) / _ \\| |  _|  _|  ");
        Console.WriteLine("| |  | |/ ___ \\ | || |\\  | |  __/ ___ \\ |_| | |___ ");
        Console.WriteLine("|_|  |_/_/   \\_\\___|_| \\_| |_| /_/   \\_\\____|_____|");
        Console.WriteLine("====================================================\n");

        Console.WriteLine("1) View Saved Passwords");
        Console.WriteLine("2) Add New Password");
        Console.WriteLine("3) Delete Password");
        Console.WriteLine("4) Logout\n");
    }

    static void PauseAndExit()
    {
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }
}
