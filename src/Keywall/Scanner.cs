using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Keywall;

public sealed record Finding(string File, string Rule);
public sealed class ScanResult
{
    public List<Finding> Findings { get; } = [];
    public List<string> Errors { get; } = [];
    public bool Clean => Findings.Count == 0 && Errors.Count == 0;
    public int Files { get; set; }
}
public sealed class Scanner
{
    public const int MaxFile = 32 * 1024 * 1024;
    const long MaxTotal = 128L * 1024 * 1024;
    const int MaxFiles = 10_000;
    long total;
    readonly List<(string Alias, byte[] Value)> known = [];
    readonly List<string> textValues = [];
    static readonly (string Name, Regex Pattern)[] Rules =
    [
        ("private-key", R(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
        ("github-token", R(@"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
        ("aws-access-key", R(@"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
        ("api-token", R(@"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,255}\b")),
        ("slack-token", R(@"\bxox[baprs]-[A-Za-z0-9-]{15,255}\b")),
        ("credential-assignment", R("(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password|smtp[_-]?(?:password|token))\\s*[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_+/=.-]{12,})"))
    ];
    static Regex R(string expression) => new(expression, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    public Scanner(IEnumerable<Secret> secrets)
    {
        foreach (var s in secrets)
        {
            var values = new[] { s.Value, Convert.ToBase64String(Encoding.UTF8.GetBytes(s.Value)), Uri.EscapeDataString(s.Value), Convert.ToHexString(Encoding.UTF8.GetBytes(s.Value)).ToLowerInvariant(), Convert.ToHexString(Encoding.UTF8.GetBytes(s.Value)) };
            foreach (var value in values.Distinct())
            {
                textValues.Add(value);
                known.Add((s.Name, Encoding.UTF8.GetBytes(value)));
                known.Add((s.Name, Encoding.Unicode.GetBytes(value)));
                known.Add((s.Name, Encoding.BigEndianUnicode.GetBytes(value)));
            }
        }
        textValues.Sort((a,b) => b.Length.CompareTo(a.Length));
    }
    public string Redact(string text)
    {
        foreach (var value in textValues) text = text.Replace(value, "[REDACTED]", StringComparison.Ordinal);
        foreach (var rule in Rules) text = rule.Pattern.Replace(text, "[REDACTED]");
        return Names.Display(text);
    }
    public ScanResult PathScan(string path)
    {
        var result = new ScanResult(); total = 0;
        if (File.Exists(path)) FileScan(path, result);
        else if (Directory.Exists(path)) Walk(path, result);
        else result.Errors.Add("Path does not exist.");
        return result;
    }
    void Walk(string path, ScanResult result, int depth = 0)
    {
        if (depth > 100) { result.Errors.Add("Directory nesting limit exceeded."); return; }
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) { result.Errors.Add("Symbolic link/reparse directory is unsupported: " + path); return; }
            foreach (var f in Directory.EnumerateFiles(path)) FileScan(f, result);
            foreach (var d in Directory.EnumerateDirectories(path)) Walk(d, result, depth + 1);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { result.Errors.Add("Cannot read directory: " + path); }
    }
    void FileScan(string path, ScanResult result)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) { result.Errors.Add("Symbolic link/reparse file is unsupported: " + path); return; }
            using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (f.Length > MaxFile) { result.Errors.Add("File exceeds 32 MiB: " + path); return; }
            var bytes = ReadBounded(f, MaxFile); Bytes(bytes, path, result);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { result.Errors.Add("Cannot read file: " + path); }
    }
    public void Bytes(byte[] bytes, string label, ScanResult result, int depth = 0)
    {
        total += bytes.Length; result.Files++;
        if (bytes.Length > MaxFile || total > MaxTotal || result.Files > MaxFiles)
            throw new UserError("Scan limit exceeded (32 MiB/file, 128 MiB total, 10000 files). Nothing uploaded.");
        foreach (var group in known.GroupBy(k => k.Alias))
            if (group.Any(k => bytes.AsSpan().IndexOf(k.Value) >= 0)) result.Findings.Add(new(label, "stored-key:" + group.Key));
        // Exact checks include binary and UTF-16. Pattern matching includes UTF-8 and BOM-marked UTF-16.
        var text = bytes.Length > 1 && bytes[0] == 0xff && bytes[1] == 0xfe ? Encoding.Unicode.GetString(bytes)
                 : bytes.Length > 1 && bytes[0] == 0xfe && bytes[1] == 0xff ? Encoding.BigEndianUnicode.GetString(bytes)
                 : Encoding.UTF8.GetString(bytes);
        try { foreach (var rule in Rules) if (rule.Pattern.IsMatch(text)) result.Findings.Add(new(label, rule.Name)); }
        catch (RegexMatchTimeoutException) { result.Errors.Add("Pattern scan timed out: " + label); }
        if (text.StartsWith("version https://git-lfs.github.com/spec/v1", StringComparison.Ordinal))
            result.Errors.Add("Git LFS payload is external and cannot be inspected: " + label);
        var ext = System.IO.Path.GetExtension(label).ToLowerInvariant();
        bool zip = bytes.Length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && ((bytes[2] == 3 && bytes[3] == 4) || (bytes[2] == 5 && bytes[3] == 6));
        if (zip || ext == ".zip")
        {
            if (depth >= 3) { result.Errors.Add("Archive nesting limit exceeded: " + label); return; }
            try
            {
                using var stream = new MemoryStream(bytes, false); using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
                if (archive.Entries.Count > MaxFiles - result.Files) { result.Errors.Add("Archive entry count exceeds limits: " + label); return; }
                foreach (var entry in archive.Entries)
                {
                    if (entry.FullName.EndsWith('/')) continue;
                    if (entry.Length > MaxFile || entry.Length + total > MaxTotal) { result.Errors.Add("Archive entry exceeds limits: " + label); break; }
                    using var input = entry.Open(); Bytes(ReadBounded(input, MaxFile), label + "!" + entry.FullName, result, depth + 1);
                }
            }
            catch (Exception e) when (e is InvalidDataException or IOException) { result.Errors.Add("Archive cannot be inspected (damaged/encrypted/unsupported): " + label); }
        }
        else if (ext is ".7z" or ".rar" or ".gz" or ".tgz" or ".tar" or ".bz2" or ".xz" or ".zst" or ".pdf" or ".doc" or ".xls" ||
                 HasMagic(bytes, [0x1f, 0x8b]) || HasMagic(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) || HasMagic(bytes, [0x52, 0x61, 0x72, 0x21]) ||
                 HasMagic(bytes, [0x25, 0x50, 0x44, 0x46]) || HasMagic(bytes, [0xd0, 0xcf, 0x11, 0xe0]) ||
                 (bytes.Length > 262 && bytes.AsSpan(257, 5).SequenceEqual("ustar"u8)))
            result.Errors.Add("Container format is unsupported: " + label);
    }
    static bool HasMagic(byte[] bytes, byte[] magic) => bytes.AsSpan().StartsWith(magic);
    public static byte[] ReadBounded(Stream stream, int max)
    {
        using var output = new MemoryStream(); var buffer = new byte[8192]; int n;
        while ((n = stream.Read(buffer)) > 0) { if (output.Length + n > max) throw new UserError("Input exceeds size limit."); output.Write(buffer, 0, n); }
        return output.ToArray();
    }
}
