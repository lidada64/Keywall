using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Keywall;

public sealed record Secret(string Name, string Value, string Note, DateTimeOffset Updated);
public sealed record UploadTarget(string Name, string Url, string? Key, string Header, string Prefix);
public sealed class VaultData
{
    public int Version { get; set; } = 1;
    public List<Secret> Secrets { get; set; } = [];
    public List<UploadTarget> Targets { get; set; } = [];
}
public sealed record Envelope(int Version, string Mode, string Salt, int Iterations, string Nonce, string Tag, string Data);

public sealed class Vault : IDisposable
{
    public const int Iterations = 600_000;
    public const int MaxBytes = 4 * 1024 * 1024;
    readonly string path;
    readonly FileStream gate;
    byte[]? key;
    byte[] salt = [];
    string mode = "password";
    public VaultData Data { get; private set; } = new();
    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Keywall", "vault.json");

    public Vault(string path)
    {
        this.path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(this.path)!);
        if (File.Exists(this.path) && (File.GetAttributes(this.path) & FileAttributes.ReparsePoint) != 0)
            throw new UserError("Vault cannot be a symbolic link.");
        try { gate = new FileStream(this.path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { throw new UserError("Vault is in use. Close the other command and retry."); }
    }
    public bool Exists => File.Exists(path);
    public void Initialize(string selectedMode, string? password)
    {
        if (Exists) throw new UserError("Vault already exists; it was not overwritten.");
        mode = selectedMode;
        if (mode == "password")
        {
            if (password is null || password.EnumerateRunes().Count() < 8) throw new UserError("Use a master password of at least 8 characters.");
            salt = RandomNumberGenerator.GetBytes(16);
            key = Derive(password, salt);
        }
        else if (mode != "windows" || !OperatingSystem.IsWindows()) throw new UserError("Windows mode requires Windows.");
        Save();
    }
    public string ReadMode() => ReadEnvelope().Mode;
    Envelope ReadEnvelope()
    {
        if (!Exists) throw new UserError("No vault. Run keywall init first.");
        if (new FileInfo(path).Length > MaxBytes) throw new UserError("Vault exceeds the supported size.");
        var e = JsonSerializer.Deserialize<Envelope>(File.ReadAllBytes(path)) ?? throw new UserError("Invalid vault.");
        if (e.Version != 1 || (e.Mode != "password" && e.Mode != "windows")) throw new UserError("Unsupported vault format.");
        return e;
    }
    public string SessionSalt => ReadEnvelope().Salt;
    public byte[] ExportSessionKey() => key?.ToArray() ?? throw new UserError("No password session key is available.");
    public void Open(string? password) => OpenCore(password, null);
    public void OpenWithSession(byte[] sessionKey) => OpenCore(null, sessionKey);
    void OpenCore(string? password, byte[]? sessionKey)
    {
        var e = ReadEnvelope(); mode = e.Mode;
        byte[]? plain = null;
        try
        {
            if (mode == "password")
            {
                if (e.Iterations != Iterations) throw new UserError("Unsupported password derivation settings.");
                salt = Convert.FromBase64String(e.Salt);
                if (salt.Length != 16) throw new UserError("Invalid vault salt.");
                if (key is not null) CryptographicOperations.ZeroMemory(key);
                key = sessionKey is null ? Derive(password ?? throw new UserError("Master password required."), salt) : sessionKey.ToArray();
                if (key.Length != 32) throw new UserError("Invalid unlock session.");
                var encrypted = Convert.FromBase64String(e.Data);
                plain = new byte[encrypted.Length];
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(Convert.FromBase64String(e.Nonce), encrypted, Convert.FromBase64String(e.Tag), plain, Aad);
            }
            else plain = Dpapi.Unprotect(Convert.FromBase64String(e.Data));
            Data = JsonSerializer.Deserialize<VaultData>(plain) ?? throw new UserError("Invalid vault contents.");
            if (Data.Version != 1) throw new UserError("Unsupported vault contents.");
        }
        catch (CryptographicException) { throw new UserError("Unlock failed: wrong password/account or damaged vault."); }
        finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }
    static readonly byte[] Aad = Encoding.UTF8.GetBytes("keywall/v1/password/pbkdf2-sha256/600000");
    static byte[] Derive(string password, byte[] salt)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        try { return Rfc2898DeriveBytes.Pbkdf2(bytes, salt, Iterations, HashAlgorithmName.SHA256, 32); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Save()
    {
        var plain = JsonSerializer.SerializeToUtf8Bytes(Data);
        if (plain.Length > MaxBytes / 2) throw new UserError("Vault capacity exceeded.");
        try
        {
            Envelope e;
            if (mode == "password")
            {
                var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16]; var cipher = new byte[plain.Length];
                using var aes = new AesGcm(key ?? throw new UserError("Vault is locked."), 16);
                aes.Encrypt(nonce, plain, cipher, tag, Aad);
                e = new(1, mode, Convert.ToBase64String(salt), Iterations, Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(cipher));
            }
            else e = new(1, mode, "", 0, "", "", Convert.ToBase64String(Dpapi.Protect(plain)));
            var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var f = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { var encoded = JsonSerializer.SerializeToUtf8Bytes(e); f.Write(encoded); f.Flush(true); }
                File.Move(temp, path, true);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public Secret Get(string name) => Data.Secrets.SingleOrDefault(s => s.Name == name) ?? throw new UserError("Unknown key alias.");
    public void Put(string name, string value, string note)
    {
        Names.Validate(name);
        if (value.Length < 8 || value.Length > 4096 || value.Any(char.IsControl)) throw new UserError("Key must contain 8–4096 characters and no control characters.");
        if (Data.Secrets.Count >= 500 && !Data.Secrets.Any(s => s.Name == name)) throw new UserError("Limit: 500 keys.");
        Data.Secrets.RemoveAll(s => s.Name == name);
        Data.Secrets.Add(new(name, value, note, DateTimeOffset.UtcNow)); Save();
    }
    public void Dispose() { if (key is not null) CryptographicOperations.ZeroMemory(key); gate.Dispose(); }
}
public static class Names
{
    public static void Validate(string name)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(name, @"\A[a-zA-Z0-9][a-zA-Z0-9_./-]{0,99}\z"))
            throw new UserError("Alias must use 1–100 letters, digits, _, ., / or -.");
    }
    public static string Display(string value) => string.Concat(value.Select(c => char.IsControl(c) ? '?' : c));
}
static class Dpapi
{
    [StructLayout(LayoutKind.Sequential)] struct Blob { public int Length; public IntPtr Pointer; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    public static byte[] Protect(byte[] data) => Transform(data, true);
    public static byte[] Unprotect(byte[] data) => Transform(data, false);
    static byte[] Transform(byte[] data, bool encrypt)
    {
        if (!OperatingSystem.IsWindows()) throw new UserError("This vault is bound to a Windows account.");
        var p = Marshal.AllocHGlobal(data.Length); var input = new Blob { Length = data.Length, Pointer = p };
        try
        {
            Marshal.Copy(data, 0, p, data.Length);
            Blob output;
            bool ok = encrypt ? CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                              : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new CryptographicException("DPAPI operation failed.");
            try
            {
                var result = new byte[output.Length]; Marshal.Copy(output.Pointer, result, 0, result.Length);
                Marshal.Copy(new byte[output.Length], 0, output.Pointer, output.Length); return result;
            }
            finally { LocalFree(output.Pointer); }
        }
        finally { Marshal.Copy(new byte[data.Length], 0, p, data.Length); Marshal.FreeHGlobal(p); }
    }
}
