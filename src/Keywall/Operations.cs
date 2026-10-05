using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Keywall;

public static class Operations
{
    public static async Task<int> Run(Secret secret, string variable, string[] command, Scanner scanner)
    {
        if (!Regex.IsMatch(variable, @"\A[A-Za-z_][A-Za-z0-9_]*\z") || variable.Equals("PATH", StringComparison.OrdinalIgnoreCase) || variable.StartsWith("KEYWALL_", StringComparison.OrdinalIgnoreCase))
            throw new UserError("Invalid or reserved environment variable name.");
        if (command.Length == 0) throw new UserError("Missing executable after --.");
        var start = new ProcessStartInfo(command[0]) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in command.Skip(1)) start.ArgumentList.Add(arg);
        // Reject accidental literal secret arguments, which would enter process listings.
        if (command.Any(a => a.Contains(secret.Value, StringComparison.Ordinal))) throw new UserError("Do not place a key in command arguments.");
        start.Environment[variable] = secret.Value;
        using var child = Process.Start(start) ?? throw new UserError("Cannot start executable.");
        try
        {
            void Abort() { if (!child.HasExited) child.Kill(true); }
            await Task.WhenAll(Filter(child.StandardOutput, Console.Out, scanner, Abort), Filter(child.StandardError, Console.Error, scanner, Abort));
            await child.WaitForExitAsync(); return child.ExitCode;
        }
        catch
        {
            if (!child.HasExited) child.Kill(true);
            throw;
        }
    }
    static async Task Filter(StreamReader input, TextWriter output, Scanner scanner, Action abort)
    {
        try
        {
        // Hold each logical line until checked; never release a secret split across pipe chunks.
        var line = new StringBuilder(); var buffer = new char[4096]; int n;
        while ((n = await input.ReadAsync(buffer)) > 0)
        {
            for (int i = 0; i < n; i++)
            {
                if (buffer[i] == '\n') { await output.WriteLineAsync(scanner.Redact(line.ToString().TrimEnd('\r'))); line.Clear(); }
                else { line.Append(buffer[i]); if (line.Length > 65536) throw new UserError("Child output line exceeded safety limit; process stopped."); }
            }
        }
        if (line.Length > 0) await output.WriteAsync(scanner.Redact(line.ToString()));
        }
        catch { abort(); throw; }
    }
    public static void ValidateTarget(UploadTarget target)
    {
        Names.Validate(target.Name);
        if (!Uri.TryCreate(target.Url, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "")
            throw new UserError("Target must be an HTTPS URL without user info, query or fragment.");
        if (target.Header is not ("Authorization" or "X-API-Key")) throw new UserError("Supported credential headers: Authorization, X-API-Key.");
        if (target.Prefix.Length > 32 || target.Prefix.Any(char.IsControl)) throw new UserError("Invalid header prefix.");
    }
    public static async Task<string> Upload(string path, UploadTarget target, VaultData data, HttpMessageHandler? testHandler = null)
    {
        ValidateTarget(target);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UserError("Cannot upload a symbolic link.");
        byte[] snapshot;
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) snapshot = Scanner.ReadBounded(file, Scanner.MaxFile);
        try
        {
            var scanner = new Scanner(data.Secrets); var report = new ScanResult(); scanner.Bytes(snapshot, Path.GetFileName(path), report);
            RequireClean(report, scanner);
            // Upload exactly the bytes that passed the scan. Do not reopen the original file.
            using var handler = testHandler ?? new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };
            using var request = new HttpRequestMessage(HttpMethod.Put, target.Url);
            request.Content = new ByteArrayContent(snapshot); request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            if (target.Key is not null)
            {
                var key = data.Secrets.SingleOrDefault(s => s.Name == target.Key) ?? throw new UserError("Target key no longer exists.");
                request.Headers.Add(target.Header, target.Prefix + key.Value);
            }
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            if (!response.IsSuccessStatusCode) throw new UserError("Upload failed (HTTP " + (int)response.StatusCode + "); redirects are not followed.");
            return Convert.ToHexString(SHA256.HashData(snapshot)).ToLowerInvariant();
        }
        finally { CryptographicOperations.ZeroMemory(snapshot); }
    }
    public static void RequireClean(ScanResult report, Scanner scanner)
    {
        foreach (var f in report.Findings.Take(100)) Console.Error.WriteLine(scanner.Redact($"BLOCK {f.File} [{f.Rule}]"));
        foreach (var e in report.Errors.Take(100)) Console.Error.WriteLine(scanner.Redact("UNCHECKED " + e));
        if (!report.Clean) throw new UserError($"Blocked: {report.Findings.Count} findings, {report.Errors.Count} unchecked items.", 2);
    }
    public static byte[] Git(string repo, params string[] args)
    {
        var p = new ProcessStartInfo("git") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        p.ArgumentList.Add("-C"); p.ArgumentList.Add(Path.GetFullPath(repo));
        foreach (var a in args) p.ArgumentList.Add(a);
        using var process = Process.Start(p) ?? throw new UserError("git is not installed.");
        var errors = process.StandardError.ReadToEndAsync();
        byte[] bytes;
        try { bytes = Scanner.ReadBounded(process.StandardOutput.BaseStream, Scanner.MaxFile); }
        catch { if (!process.HasExited) process.Kill(true); throw; }
        process.WaitForExit(); errors.GetAwaiter().GetResult();
        if (process.ExitCode != 0) throw new UserError("Git command failed; check repository, remote and authentication in your own terminal.");
        return bytes;
    }
    public static string GitText(string repo, params string[] args) => Encoding.UTF8.GetString(Git(repo, args)).Trim();
    static bool IsOid(string value) => Regex.IsMatch(value, @"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z");
    public static ScanResult CheckTip(string repo, string tip, Scanner scanner, string? previousTip = null)
    {
        if (!IsOid(tip)) throw new UserError("Invalid Git object ID.");
        var revisions = new List<string> { "rev-list", "--objects", tip };
        if (previousTip is not null)
        {
            if (!IsOid(previousTip)) throw new UserError("Invalid remote Git object ID.");
            try { Git(repo, "cat-file", "-e", previousTip + "^{object}"); }
            catch (UserError) { throw new UserError("Remote base is unavailable locally. Run git fetch before pushing; no objects were skipped."); }
            revisions.Add("^" + previousTip);
        }
        // Ignore blobs already reachable from the advertised remote ref, but inspect
        // every outgoing blob even if a later commit deletes or ignores its path.
        var lines = GitText(repo, revisions.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length > 30000) throw new UserError("Git history exceeds the first-version scan limit (30000 objects).");
        var result = new ScanResult();
        foreach (var line in lines)
        {
            int space = line.IndexOf(' '); var oid = space < 0 ? line.Trim() : line[..space];
            if (!IsOid(oid)) throw new UserError("Unexpected Git object listing.");
            if (GitText(repo, "cat-file", "-t", oid) != "blob") continue;
            if (!long.TryParse(GitText(repo, "cat-file", "-s", oid), out var length) || length > Scanner.MaxFile)
            { result.Errors.Add("Git blob exceeds 32 MiB: " + oid); continue; }
            var label = space < 0 ? oid : line[(space + 1)..].Trim();
            scanner.Bytes(Git(repo, "cat-file", "blob", oid), label, result);
        }
        return result;
    }
    public static void Push(string repo, string remote, string branch, Scanner scanner)
    {
        if (!Regex.IsMatch(remote, @"\A[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\z")) throw new UserError("Use a configured remote name, not a URL.");
        Git(repo, "check-ref-format", "refs/heads/" + branch);
        var tip = GitText(repo, "rev-parse", "--verify", "refs/heads/" + branch + "^{commit}");
        var remoteUrl = GitText(repo, "remote", "get-url", "--push", remote);
        // Fixed destination captured once; refuse multiple push URLs instead of inspecting only one.
        var allUrls = GitText(repo, "remote", "get-url", "--push", "--all", remote).Split('\n');
        if (allUrls.Length != 1 || remoteUrl.StartsWith('-')) throw new UserError("Exactly one safe push URL is required.");
        var advertised = GitText(repo, "ls-remote", "--heads", remoteUrl, "refs/heads/" + branch);
        var old = advertised.Length == 0 ? "" : advertised.Split('\t')[0];
        if (old.Length > 0)
        {
            if (!IsOid(old)) throw new UserError("Unexpected remote ref.");
            // Refuse non-fast-forward updates. Missing old object also blocks: fetch first.
            Git(repo, "merge-base", "--is-ancestor", old, tip);
        }
        RequireClean(CheckTip(repo, tip, scanner, old.Length > 0 ? old : null), scanner);
        // Pin both local commit and expected remote ref, closing scan/push races.
        Git(repo, "-c", "push.followTags=false", "push", "--porcelain", "--no-follow-tags", "--recurse-submodules=no",
            "--force-with-lease=refs/heads/" + branch + ":" + old, remoteUrl, tip + ":refs/heads/" + branch);
        Console.WriteLine("Pushed inspected commit " + tip + ".");
    }
    public static void CheckHook(string repo, Scanner scanner)
    {
        string? line;
        while ((line = Console.ReadLine()) is not null)
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 4 || !IsOid(parts[1]) || !IsOid(parts[3])) throw new UserError("Invalid pre-push input.");
            if (parts[1].All(c => c == '0')) continue;
            RequireClean(CheckTip(repo, parts[1], scanner, parts[3].All(c => c == '0') ? null : parts[3]), scanner);
        }
    }
}
