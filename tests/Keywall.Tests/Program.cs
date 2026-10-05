using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Keywall;

internal static class Tests
{
    const string MasterPhrase = "Only-A-Test-Passphrase-2026";
    const string Value = "FixtureKey_XYZabcdefgh0123456789";
    static readonly Secret Secret = new("test/dev", Value, "fixture", DateTimeOffset.UtcNow);
    static int count;
    static string root = "";
    static void Check(bool value, string name) { if (!value) throw new Exception("FAIL " + name); count++; Console.WriteLine("PASS " + name); }
    static void Fails(Action action, string name)
    { bool failed = false; try { action(); } catch (UserError) { failed = true; } Check(failed, name); }
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "_session") return await Session.Serve(args[1]);
        if (args.Length > 0 && args[0] == "--emit")
        {
            var key = Environment.GetEnvironmentVariable("FIXTURE_TOKEN")!;
            Console.Write(key[..7]); Console.Out.Flush(); await Task.Delay(20); Console.WriteLine(key[7..]);
            Console.Error.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(key)));
            Console.Write("safe-final"); return 7;
        }
        if (args.Length > 0 && args[0] == "--flood") { Console.Write(new string('a', 70000)); Console.Out.Flush(); await Task.Delay(10000); return 0; }
        root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.test-data", Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(root);
        try
        {
            VaultTests(); ScannerTests(); await RunTests(); await UploadTests(); GitTests(); await CliTests(); await SessionTests();
            Console.WriteLine($"All {count} checks passed. Test artifacts: {root}"); return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
    static void VaultTests()
    {
        var shortPath = Path.Combine(root, "eight-character-vault.json");
        using (var shortVault = new Vault(shortPath))
        {
            Fails(() => shortVault.Initialize("password", "1234567"), "seven-character master phrase rejected");
            Check(!File.Exists(shortPath), "rejected short phrase creates no vault file");
            shortVault.Initialize("password", "12345678");
        }
        using (var shortVault = new Vault(shortPath)) { shortVault.Open("12345678"); Check(shortVault.Data.Version == 1, "eight-character master phrase accepted and reopens"); }
        using (var unicodeVault = new Vault(Path.Combine(root, "unicode-minimum.json")))
            Fails(() => unicodeVault.Initialize("password", "😀😀😀😀"), "four supplementary Unicode characters are not eight characters");
        var path = Path.Combine(root, "password-vault.json");
        using (var v = new Vault(path))
        {
            v.Initialize("password", MasterPhrase); v.Put(Secret.Name, Secret.Value, Secret.Note);
            Check(!File.ReadAllText(path).Contains(Value), "vault ciphertext contains no plaintext key");
            Fails(() => { using var other = new Vault(path); }, "concurrent writer blocked");
            Fails(() => v.Initialize("password", MasterPhrase), "init cannot overwrite vault");
            Fails(() => v.Put("unsafe\nname", Value, ""), "unsafe alias rejected");
        }
        using (var v = new Vault(path)) { v.Open(MasterPhrase); Check(v.Get(Secret.Name).Value == Value, "password vault survives reopen"); }
        using (var v = new Vault(path)) Fails(() => v.Open("wrong password"), "wrong password rejected");
        var e = JsonSerializer.Deserialize<Envelope>(File.ReadAllBytes(path))!;
        var tag = Convert.FromBase64String(e.Tag); tag[0] ^= 1;
        File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(e with { Tag = Convert.ToBase64String(tag) }));
        using (var v = new Vault(path)) Fails(() => v.Open(MasterPhrase), "tampered ciphertext rejected");
        if (OperatingSystem.IsWindows())
        {
            var windows = Path.Combine(root, "windows-vault.json");
            using (var v = new Vault(windows)) { v.Initialize("windows", null); v.Put(Secret.Name, Value, ""); }
            using (var v = new Vault(windows)) { v.Open(null); Check(v.Get(Secret.Name).Value == Value, "Windows DPAPI roundtrip"); }
            Check(!File.ReadAllText(windows).Contains(Value), "DPAPI file hides plaintext");
        }
    }
    static void ScannerTests()
    {
        foreach (var (label, bytes) in new[]
        {
            ("raw", Encoding.UTF8.GetBytes(Value)), ("binary", new byte[] { 0, 1 }.Concat(Encoding.UTF8.GetBytes(Value)).ToArray()),
            ("UTF16", Encoding.Unicode.GetBytes(Value)), ("base64", Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(Value)))),
            ("hex", Encoding.UTF8.GetBytes(Convert.ToHexString(Encoding.UTF8.GetBytes(Value))))
        })
        {
            var report = new ScanResult(); new Scanner([Secret]).Bytes(bytes, "fixture.bin", report);
            Check(report.Findings.Any(f => f.Rule == "stored-key:test/dev"), "exact scan " + label);
        }
        var generic = new ScanResult(); new Scanner([]).Bytes(Encoding.UTF8.GetBytes("ghp_" + new string('A', 36)), "token.txt", generic);
        Check(!generic.Clean, "unregistered provider token detected");
        var zip = Zip(Encoding.UTF8.GetBytes(Value)); var nested = Zip(zip, "inner.zip");
        var zr = new ScanResult(); new Scanner([Secret]).Bytes(nested, "payload.zip", zr);
        Check(zr.Findings.Any(f => f.File.Contains("inner.zip!fixture.txt")), "nested ZIP inspected");
        var bad = new ScanResult(); new Scanner([]).Bytes([0x50, 0x4b, 3, 4], "bad.zip", bad);
        Check(bad.Errors.Count == 1, "damaged ZIP blocks");
        var lfs = new ScanResult(); new Scanner([]).Bytes(Encoding.UTF8.GetBytes("version https://git-lfs.github.com/spec/v1\noid sha256:fixture\n"), "large.dat", lfs);
        Check(lfs.Errors.Count == 1, "external Git LFS payload fails closed");
        var utf16 = new ScanResult(); new Scanner([]).Bytes(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("ghp_" + new string('B', 36))).ToArray(), "unicode.txt", utf16);
        Check(!utf16.Clean, "unregistered UTF16 token detected");
        using (var many = new MemoryStream())
        {
            using (var z = new ZipArchive(many, ZipArchiveMode.Create, true)) for (int i = 0; i < 10001; i++) z.CreateEntry(i + "/");
            var report = new ScanResult(); new Scanner([]).Bytes(many.ToArray(), "entries.zip", report);
            Check(report.Errors.Count == 1, "ZIP directory entry bomb fails closed");
        }
        var unsupported = new ScanResult(); new Scanner([]).Bytes([0x1f, 0x8b], "disguised.bin", unsupported);
        Check(unsupported.Errors.Count == 1, "unsupported compression detected by magic");
        var clean = new ScanResult(); new Scanner([Secret]).Bytes(Encoding.UTF8.GetBytes("safe content"), "safe.txt", clean);
        Check(clean.Clean, "clean file passes");
        var scanner = new Scanner([Secret]); Check(!scanner.Redact(Value + "\n" + Value).Contains(Value), "redaction removes stored values");
        Fails(() => new Scanner([]).Bytes(new byte[Scanner.MaxFile + 1], "huge", new ScanResult()), "oversize scan fails closed");
    }
    static byte[] Zip(byte[] value, string name = "fixture.txt")
    {
        using var m = new MemoryStream(); using (var z = new ZipArchive(m, ZipArchiveMode.Create, true)) { using var f = z.CreateEntry(name).Open(); f.Write(value); } return m.ToArray();
    }
    static async Task RunTests()
    {
        var output = Console.Out; var error = Console.Error; var o = new StringWriter(); var e = new StringWriter(); int result;
        Console.SetOut(o); Console.SetError(e);
        try { result = await Operations.Run(Secret, "FIXTURE_TOKEN", ["dotnet", typeof(Tests).Assembly.Location, "--emit"], new Scanner([Secret])); }
        finally { Console.SetOut(output); Console.SetError(error); }
        Check(result == 7, "run preserves child exit code");
        Check(!o.ToString().Contains(Value) && !e.ToString().Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(Value))) && o.ToString().Contains("[REDACTED]"), "split output and encoded stderr masked");
        Check(o.ToString().EndsWith("safe-final"), "output without final newline preserved");
        var timer = System.Diagnostics.Stopwatch.StartNew(); bool blocked = false;
        try { await Operations.Run(Secret, "FIXTURE_TOKEN", ["dotnet", typeof(Tests).Assembly.Location, "--flood"], new Scanner([Secret])); }
        catch (UserError) { blocked = true; }
        Check(blocked && timer.Elapsed.TotalSeconds < 5, "oversized output terminates child promptly");
    }
    sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> execute) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => execute(request); }
    static async Task UploadTests()
    {
        var file = Path.Combine(root, "upload.txt"); File.WriteAllText(file, "safe snapshot");
        var data = new VaultData { Secrets = [Secret] }; var target = new UploadTarget("fixture", "https://example.com/upload", Secret.Name, "Authorization", "Bearer ");
        byte[]? received = null; bool auth = false;
        var handler = new Handler(async r =>
        {
            File.WriteAllText(file, Value); received = await r.Content!.ReadAsByteArrayAsync();
            auth = r.Headers.Authorization?.Parameter == Value;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var hash = await Operations.Upload(file, target, data, handler);
        Check(Encoding.UTF8.GetString(received!) == "safe snapshot", "upload uses scanned snapshot despite source mutation");
        Check(hash == Convert.ToHexString(SHA256.HashData(received!)).ToLowerInvariant() && auth, "upload hash and scoped auth");
        bool sent = false; bool blocked = false;
        try { await Operations.Upload(file, target, data, new Handler(_ => { sent = true; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)); })); }
        catch (UserError) { blocked = true; }
        Check(blocked && !sent, "leaked key blocks before HTTP request");
        File.WriteAllText(file, "clean"); blocked = false;
        try { await Operations.Upload(file, target, data, new Handler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect)))); }
        catch (UserError) { blocked = true; }
        Check(blocked, "HTTP redirect rejected");
        Fails(() => Operations.ValidateTarget(target with { Url = "http://example.com/upload" }), "HTTP target rejected");
        Fails(() => Operations.ValidateTarget(target with { Url = "https://example.com/?token=abc" }), "query credential target rejected");
    }
    static string Repo(string name)
    {
        var repo = Path.Combine(root, name); Directory.CreateDirectory(repo);
        Operations.Git(repo, "init", "-b", "main"); Operations.Git(repo, "config", "user.name", "Keywall Test"); Operations.Git(repo, "config", "user.email", "test@example.invalid"); return repo;
    }
    static void Commit(string repo, string content)
    {
        File.WriteAllText(Path.Combine(repo, "file.txt"), content); Operations.Git(repo, "add", "file.txt"); Operations.Git(repo, "commit", "-m", "fixture");
    }
    static void GitTests()
    {
        var repo = Repo("leaky-repo"); Commit(repo, Value); Commit(repo, "removed secret");
        var tip = Operations.GitText(repo, "rev-parse", "HEAD");
        Check(!Operations.CheckTip(repo, tip, new Scanner([Secret])).Clean, "deleted key in Git history still blocks");
        var clean = Repo("clean-repo"); Commit(clean, "clean");
        var remote = Path.Combine(root, "remote.git"); Directory.CreateDirectory(remote); Operations.Git(remote, "init", "--bare"); Operations.Git(clean, "remote", "add", "origin", remote);
        Operations.Push(clean, "origin", "main", new Scanner([Secret]));
        Check(Operations.GitText(remote, "rev-parse", "refs/heads/main") == Operations.GitText(clean, "rev-parse", "HEAD"), "clean pinned branch push works against local bare remote");
        Operations.Git(repo, "remote", "add", "origin", remote);
        Fails(() => Operations.Push(repo, "origin", "main", new Scanner([Secret])), "non-fast-forward push refused");
        var leakRemote = Path.Combine(root, "leak-remote.git"); Directory.CreateDirectory(leakRemote); Operations.Git(leakRemote, "init", "--bare"); Operations.Git(repo, "remote", "add", "empty", leakRemote);
        Fails(() => Operations.Push(repo, "empty", "main", new Scanner([Secret])), "secret history push blocked");
        Check(Operations.GitText(repo, "ls-remote", "--heads", leakRemote) == "", "blocked push creates no remote branch");
    }
    static async Task CliTests()
    {
        var path = Path.Combine(root, "cli.json"); var output = Console.Out; var error = Console.Error; var input = Console.In;
        var o = new StringWriter(); var e = new StringWriter(); Console.SetOut(o); Console.SetError(e);
        int created, added, found, revealed;
        try
        {
            Console.SetIn(new StringReader(MasterPhrase + "\n")); created = await Keywall.Program.Main(["--vault", path, "--password-stdin", "init"]);
            Console.SetIn(new StringReader(MasterPhrase + "\n" + Value + "\n")); added = await Keywall.Program.Main(["--vault", path, "--password-stdin", "add", "test/dev", "--stdin"]);
            Console.SetIn(new StringReader(MasterPhrase + "\n")); found = await Keywall.Program.Main(["--vault", path, "--password-stdin", "find", "test"]);
            Console.SetIn(new StringReader(MasterPhrase + "\n")); revealed = await Keywall.Program.Main(["--vault", path, "--password-stdin", "reveal", "test/dev"]);
        }
        finally { Console.SetOut(output); Console.SetError(error); Console.SetIn(input); }
        Check(created == 0 && added == 0 && found == 0 && o.ToString().Contains("test/dev"), "CLI init add find with explicit trusted pipes");
        Check(!o.ToString().Contains(Value) && !e.ToString().Contains(Value) && revealed != 0, "CLI never reveals key into redirected output");
    }
    static async Task SessionTests()
    {
        var output = Console.Out; var error = Console.Error; var input = Console.In;
        var helpOutput = new StringWriter(); int helpCode;
        Console.SetOut(helpOutput); Console.SetIn(new StringReader(""));
        try { helpCode = await Keywall.Program.Main(["add", "--help"]); }
        finally { Console.SetOut(output); Console.SetIn(input); }
        Check(helpCode == 0 && helpOutput.ToString().Contains("--replace") && helpOutput.ToString().Contains("--note"), "add help needs neither vault nor password");
        if (!OperatingSystem.IsWindows()) return;
        var path = Path.Combine(root, "session-vault.json"); byte[] key; string salt;
        using (var v = new Vault(path)) { v.Initialize("password", MasterPhrase); v.Put(Secret.Name, Value, "session fixture"); key = v.ExportSessionKey(); salt = v.SessionSalt; }
        try
        {
            Check(!Session.IsUnlocked(path), "session starts locked");
            Session.Start(path, salt, key);
            Check(Session.IsUnlocked(path), "background session starts and responds");
            var fetched = Session.GetKey(path, salt)!;
            Check(CryptographicOperations.FixedTimeEquals(fetched, key), "correct salt gets session key");
            CryptographicOperations.ZeroMemory(fetched);
            Check(Session.GetKey(path, "different-salt") is null, "changed vault salt cannot use old session");
            Check(!Session.IsUnlocked(Path.Combine(root, "other-vault.json")), "session is scoped to one vault path");
            var result = new StringWriter(); int code;
            Console.SetOut(result); Console.SetError(new StringWriter()); Console.SetIn(new StringReader(""));
            try { code = await Keywall.Program.Main(["--vault", path, "find", "test"]); }
            finally { Console.SetOut(output); Console.SetError(error); Console.SetIn(input); }
            Check(code == 0 && result.ToString().Contains(Secret.Name) && !result.ToString().Contains(Value), "later command uses session without password input");
            using (var v = new Vault(path)) { v.Open(MasterPhrase); v.Put("new/key", "NewFixtureToken_abcdefgh", ""); }
            using (var v = new Vault(path)) { var cached = Session.GetKey(path, salt)!; try { v.OpenWithSession(cached); } finally { CryptographicOperations.ZeroMemory(cached); } Check(v.Get("new/key").Value == "NewFixtureToken_abcdefgh", "session reloads updated encrypted vault"); }
            Check(Session.Lock(path), "lock command stops session");
            Check(!Session.IsUnlocked(path) && Session.GetKey(path, salt) is null, "locked session no longer supplies keys");
            var errors = new StringWriter(); Console.SetError(errors); Console.SetIn(new StringReader(""));
            try { code = await Keywall.Program.Main(["--vault", path, "list"]); }
            finally { Console.SetError(error); Console.SetIn(input); }
            Check(code != 0, "after lock a command cannot unlock without password input");
        }
        finally { Session.Lock(path); CryptographicOperations.ZeroMemory(key); }
    }
}
