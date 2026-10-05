using System.Text;

namespace Keywall;

public sealed class UserError(string message, int code = 1) : Exception(message) { public int Code { get; } = code; }
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "_session") return await Session.Serve(args[1]);
        Console.OutputEncoding = new UTF8Encoding(false);
        try { return await Execute(args); }
        catch (UserError e) { Console.Error.WriteLine("keywall: " + Names.Display(e.Message)); return e.Code; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException or System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException or ArgumentException or System.ComponentModel.Win32Exception or HttpRequestException or TaskCanceledException)
        { Console.Error.WriteLine("keywall: operation failed (" + e.GetType().Name + "). No secret details printed."); return 1; }
    }
    static async Task<int> Execute(string[] input)
    {
        var a = new Args(input);
        var path = a.Option("--vault") ?? Vault.DefaultPath;
        bool passwordStdin = a.Flag("--password-stdin");
        bool noSession = a.Flag("--no-session");
        bool help = a.Flag("--help") || a.Flag("-h");
        string command = a.NextOr("help");
        if (help) { Help(command); return 0; }
        if (command == "help") { Help(a.NextOr("help")); a.End(); return 0; }
        if (command == "version") { a.End(); Console.WriteLine("keywall 0.1.5"); return 0; }
        if (command == "hook")
        {
            var action = a.Next(); var repo = a.Option("--repo"); bool global = a.Flag("--global"); a.End();
            if (global && repo is not null) throw new UserError("Choose --global or --repo, not both.");
            if (global) Hooks.Global(action, path); else Hooks.Manage(action, repo ?? ".", path);
            return 0;
        }
        if (command is "lock" or "logout")
        { a.End(); Session.Lock(path); Console.WriteLine("Password session locked. Future commands require the master password."); return 0; }
        if (command == "status")
        { a.End(); Console.WriteLine(Session.IsUnlocked(path) ? "Unlocked (in-memory Windows session)." : "Locked (no password session)."); return 0; }
        bool wantsLogin = command is "unlock" or "login";
        if (wantsLogin) { a.End(); if (noSession) throw new UserError("login/unlock cannot be combined with --no-session."); }
        using var vault = new Vault(path);
        if (command == "init")
        {
            bool windows = a.Flag("--windows"); a.End();
            if (windows) Console.Error.WriteLine("Windows account mode: same-account programs may decrypt this vault.");
            string? password = windows ? null : ReadSecret("New master password", passwordStdin);
            if (!windows && !passwordStdin && password != ReadSecret("Confirm master password", false)) throw new UserError("Passwords do not match.");
            vault.Initialize(windows ? "windows" : "password", password);
            if (!windows && !passwordStdin && !noSession && OperatingSystem.IsWindows()) CacheSession(vault, path);
            Console.WriteLine("Vault created."); return 0;
        }
        if (vault.ReadMode() == "password")
        {
            var sessionKey = !noSession && !passwordStdin ? Session.GetKey(path, vault.SessionSalt) : null;
            if (sessionKey is not null)
            {
                try { vault.OpenWithSession(sessionKey); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(sessionKey); }
            }
            else
            {
                if (command == "git-check" && Console.IsInputRedirected && !passwordStdin)
                    throw new UserError("Vault locked: run kw login in your terminal before git push (use the same --vault path).");
                vault.Open(ReadSecret("Master password", passwordStdin));
                if ((!passwordStdin || wantsLogin) && !noSession && OperatingSystem.IsWindows()) CacheSession(vault, path);
            }
        }
        else vault.Open(null);
        if (wantsLogin) { Console.WriteLine("Unlocked. Subsequent commands in this Windows session do not need the password. Use kw lock to lock."); return 0; }
        var scanner = new Scanner(vault.Data.Secrets);
        switch (command)
        {
            case "add":
            {
                var name = a.Next(); var note = a.Option("--note") ?? ""; bool stdin = a.Flag("--stdin"); bool replace = a.Flag("--replace"); a.End();
                if (vault.Data.Secrets.Any(s => s.Name == name) && !replace) throw new UserError("Alias exists; use --replace to update it.");
                vault.Put(name, ReadSecret("Key (hidden)", stdin), note); Console.WriteLine("Key saved; plaintext was not printed."); break;
            }
            case "list": case "find":
            {
                var query = command == "find" ? a.Next() : ""; a.End();
                foreach (var s in vault.Data.Secrets.Where(s => s.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || s.Note.Contains(query, StringComparison.OrdinalIgnoreCase)).OrderBy(s => s.Name))
                    Console.WriteLine(scanner.Redact($"{s.Name}\t{s.Note}")); break;
            }
            case "info":
            {
                var s = vault.Get(a.Next()); a.End(); Console.WriteLine(scanner.Redact($"Alias: {s.Name}\nNote: {s.Note}\nUpdated: {s.Updated:u}\nValue: [hidden]")); break;
            }
            case "remove":
            {
                var s = vault.Get(a.Next()); bool yes = a.Flag("--yes"); a.End();
                if (!yes) Confirm("Delete key alias " + scanner.Redact(s.Name) + "? Type YES: ");
                if (vault.Data.Targets.Any(t => t.Key == s.Name)) throw new UserError("Key is used by an upload target; remove the target first.");
                vault.Data.Secrets.Remove(s); vault.Save(); Console.WriteLine("Key removed."); break;
            }
            case "reveal":
            {
                var s = vault.Get(a.Next()); a.End();
                if (Console.IsOutputRedirected || Console.IsInputRedirected) throw new UserError("Reveal requires your own interactive terminal; redirected output is forbidden.");
                Confirm("This prints plaintext into terminal scrollback. Type REVEAL: ", "REVEAL"); Console.WriteLine(s.Value); break;
            }
            case "run":
            {
                var name = a.Option("--key") ?? throw new UserError("Missing --key.");
                var env = a.Option("--env") ?? throw new UserError("Missing --env.");
                var child = a.AfterSeparator(); Console.Error.WriteLine("Trusted-process mode: child receives plaintext; masking is not isolation.");
                return await Operations.Run(vault.Get(name), env, child, scanner);
            }
            case "scan":
            {
                var target = a.Next(); a.End(); var report = scanner.PathScan(target); Operations.RequireClean(report, scanner);
                Console.WriteLine($"No findings in {report.Files} inspected files. This is not a guarantee of no secrets."); break;
            }
            case "push":
            {
                var remote = a.Next(); var branch = a.Next(); var repo = a.Option("--repo") ?? "."; a.End(); Operations.Push(repo, remote, branch, scanner); break;
            }
            case "git-check":
            {
                var repo = a.Option("--repo") ?? "."; bool stdin = a.Flag("--stdin"); a.End();
                if (!stdin) throw new UserError("git-check requires --stdin (Git pre-push protocol).");
                Operations.CheckHook(repo, scanner); Console.WriteLine("Push hook scan passed."); break;
            }
            case "target":
            {
                var action = a.Next();
                if (action == "list") { a.End(); foreach (var t in vault.Data.Targets) Console.WriteLine(scanner.Redact($"{t.Name}\t{t.Url}\tkey={t.Key ?? "none"}")); }
                else if (action == "add")
                {
                    var name = a.Next(); var url = a.Next(); var key = a.Option("--key"); var header = a.Option("--header") ?? "Authorization"; var prefix = a.Option("--prefix") ?? "Bearer "; a.End();
                    if (key is not null) vault.Get(key);
                    var target = new UploadTarget(name, url, key, header, prefix); Operations.ValidateTarget(target);
                    if (vault.Data.Targets.Any(t => t.Name == name)) throw new UserError("Target exists; remove it first.");
                    if (scanner.Redact(url) != url) throw new UserError("Target URL may contain a key; use credential headers.");
                    vault.Data.Targets.Add(target); vault.Save(); Console.WriteLine("HTTPS PUT target saved.");
                }
                else if (action == "remove")
                { var name = a.Next(); a.End(); if (vault.Data.Targets.RemoveAll(t => t.Name == name) == 0) throw new UserError("Unknown target."); vault.Save(); Console.WriteLine("Target removed."); }
                else throw new UserError("Unknown target action.");
                break;
            }
            case "upload":
            {
                var file = a.Next(); var name = a.Option("--target") ?? throw new UserError("Missing --target."); a.End();
                var target = vault.Data.Targets.SingleOrDefault(t => t.Name == name) ?? throw new UserError("Unknown upload target.");
                var hash = await Operations.Upload(file, target, vault.Data); Console.WriteLine("Uploaded inspected snapshot. SHA256: " + hash); break;
            }
            case "backup":
            {
                var destination = a.Next(); a.End();
                if (vault.ReadMode() != "password") throw new UserError("Windows-bound vaults are not portable; backup requires password mode.");
                File.Copy(Path.GetFullPath(path), Path.GetFullPath(destination), false); Console.WriteLine("Encrypted backup saved. Recovery requires your master password."); break;
            }
            default: throw new UserError("Unknown command. Run keywall help.");
        }
        return 0;
    }
    public static string ReadSecret(string prompt, bool stdin)
    {
        if (stdin)
        {
            var line = new StringBuilder(); int c;
            while ((c = Console.In.Read()) != -1 && c != '\n') { if (line.Length >= 4096) throw new UserError("Input too long."); line.Append((char)c); }
            return line.ToString().TrimEnd('\r');
        }
        if (Console.IsInputRedirected) throw new UserError("Interactive hidden input required; explicitly use --stdin / --password-stdin for a trusted pipe.");
        Console.Error.Write(prompt + ": "); var buffer = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); return buffer.ToString(); }
            if (key.Key == ConsoleKey.Backspace) { if (buffer.Length > 0) buffer.Length--; }
            else if (!char.IsControl(key.KeyChar)) { if (buffer.Length >= 4096) throw new UserError("Input too long."); buffer.Append(key.KeyChar); }
        }
    }
    static void Confirm(string prompt, string expected = "YES")
    {
        if (Console.IsInputRedirected) throw new UserError("Interactive confirmation required.");
        Console.Error.Write(prompt); if (Console.ReadLine() != expected) throw new UserError("Cancelled.");
    }
    static void CacheSession(Vault vault, string path)
    {
        var key = vault.ExportSessionKey();
        try { Session.Start(path, vault.SessionSalt, key); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(key); }
    }
    static void Help(string topic = "help")
    {
        if (topic == "hook")
        {
            Console.WriteLine("""
                用法：kw hook install|status|remove [--global | --repo PATH] [--vault PATH]
                install  为指定仓库安装 pre-push 检查，保留并串联已有钩子。
                status   查看是否启用；remove 卸载并恢复原钩子。
                默认操作当前仓库；不是全局设置，新仓库需要单独启用。
                --global 设置全局默认，覆盖继承全局 hooksPath 的现有和新仓库；保留原钩子执行。
                仓库自己的 core.hooksPath 会覆盖全局设置。全局卸载恢复原配置。
                已设置 core.hooksPath 时拒绝自动修改，请手动接入 kw git-check --stdin。
                推送前执行 kw login；锁定、检查异常或发现密钥都会阻止推送。
                Git 的 --no-verify 或禁用 hooks 设置可以绕过此检查。
                """); return;
        }
        if (topic == "add")
        {
            Console.WriteLine("""
                用法：kw add <名称> [--note "备注"] [--replace] [--stdin]
                <名称>      必填，例如 github/personal、service/dev。它是别名，不是 key 的值。
                --note      可选，填写用途备注；含空格的备注加引号。
                --replace   可选，覆盖已有同名 key；未指定时拒绝覆盖。
                --stdin     可选，仅用于可信程序管道；通常不用，默认隐藏输入 key。
                --vault     可选，指定保险库路径；否则使用默认保险库。

                示例：kw add github/personal --note "个人 GitHub token"
                      kw add github/personal --replace
                第一次需要主密码；解锁会话有效时只需隐藏输入 key。
                查看所有命令：kw --help
                """); return;
        }
        Console.WriteLine("""
        keywall 0.1.5 — local CLI key vault and upload checks
        Global: --vault PATH, --no-session, --password-stdin (trusted input pipe only)
        login | unlock                    Unlock once for this Windows logon session
        lock | logout | status            Lock the session or inspect its state
        init [--windows]                  Password vault by default; Windows mode binds to account
        add ALIAS [--note TEXT] [--replace] [--stdin]
        add --help                        Show argument details and examples without unlocking
        list | find QUERY | info ALIAS | remove ALIAS [--yes]
        reveal ALIAS                      Explicit plaintext display in your interactive terminal
        run --key ALIAS --env VARIABLE -- EXECUTABLE ARG...
        scan PATH                         Stored-key and common-pattern scan; ZIP inspection
        push REMOTE BRANCH [--repo PATH]   Scan history, pin commit and remote ref, push one branch
        git-check --stdin [--repo PATH]    Optional pre-push hook protocol
        hook install|status|remove [--global | --repo PATH]   Guard ordinary git push
        target add NAME HTTPS_URL [--key ALIAS] [--header Authorization|X-API-Key] [--prefix TEXT]
        target list | target remove NAME
        upload FILE --target NAME         HTTPS PUT of exactly the inspected bytes; no redirects
        backup PATH                       Copy password-encrypted vault without overwriting
        version | help
        Exit codes: 0 success, 1 error, 2 scan blocked. run returns the child's exit code.
        Protects against accidental leaks through these paths; not a system firewall or an Agent sandbox.
        """);
    }
}
public sealed class Args
{
    readonly List<string> args;
    public Args(string[] args) => this.args = [.. args];
    int Boundary => args.IndexOf("--") is var i && i >= 0 ? i : args.Count;
    public string? Option(string name)
    {
        int i = args.FindIndex(0, Boundary, a => a == name);
        if (i < 0) return null;
        if (i + 1 >= Boundary) throw new UserError("Missing value for " + name);
        var value = args[i + 1]; args.RemoveRange(i, 2);
        if (args.Take(Boundary).Contains(name)) throw new UserError("Repeated option " + name);
        return value;
    }
    public bool Flag(string name)
    {
        int i = args.FindIndex(0, Boundary, a => a == name);
        if (i < 0) return false; args.RemoveAt(i); return true;
    }
    public string NextOr(string fallback) => args.Count == 0 ? fallback : Next();
    public string Next()
    {
        if (args.Count == 0 || args[0].StartsWith('-')) throw new UserError("Missing positional argument or unknown option.");
        var result = args[0]; args.RemoveAt(0); return result;
    }
    public string[] AfterSeparator()
    {
        if (args.Count == 0 || args[0] != "--" || args.Count == 1) throw new UserError("Place child executable after --; unexpected options are not accepted.");
        var result = args.Skip(1).ToArray(); args.Clear(); return result;
    }
    public void End() { if (args.Count != 0) throw new UserError("Unexpected argument. Run keywall help."); }
}
