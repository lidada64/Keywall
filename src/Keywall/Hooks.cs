using System.Text;
using System.Text.Json;

namespace Keywall;

public static class Hooks
{
    sealed record Manifest(string Script, bool HadOriginal);
    sealed record GlobalManifest(string PreviousGlobal, Dictionary<string, string> Scripts);
    static readonly string[] HookNames = ["applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate", "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit", "post-index-change"];
    static string Quote(string value)
    {
        if (value.Any(char.IsControl)) throw new UserError("Hook paths cannot contain control characters.");
        return "'" + value.Replace("'", "'\"'\"'") + "'";
    }
    static string ShellPath(string value) => OperatingSystem.IsWindows() ? value.Replace('\\', '/') : value;
    static string Executable()
    {
        var executable = Environment.ProcessPath ?? throw new UserError("Cannot locate Keywall executable.");
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            throw new UserError("Install hooks using the packaged kw executable.");
        return executable;
    }
    static void WriteHook(string path, string script)
    {
        File.WriteAllText(path, script, new UTF8Encoding(false));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    static string PushScript(string executable, string vault, string previousSetup, string previous)
    {
        return "#!/bin/sh\n# Keywall managed pre-push hook v1\n" + previousSetup +
            "refs=''\ncount=0\nwhile IFS= read -r line; do\n  count=$((count + 1))\n  [ \"$count\" -le 10000 ] || exit 1\n  refs=\"$refs$line\n\"\ndone\n" +
            "printf '%s' \"$refs\" | " + Quote(ShellPath(executable)) + " --vault " + Quote(ShellPath(Path.GetFullPath(vault))) + " git-check --stdin >&2\n" +
            "result=$?\nif [ \"$result\" -ne 0 ]; then\n  echo 'Keywall blocked push. Unlock with kw login if needed; fix reported findings before retrying.' >&2\n  exit \"$result\"\nfi\n" +
            (previous.Length > 0 ? "if [ -x " + previous + " ]; then\n  printf '%s' \"$refs\" | " + previous + " \"$@\"\n  exit $?\nfi\n" : "") + "exit 0\n";
    }
    public static void Global(string action, string vault)
    {
        if (action is not ("install" or "status" or "remove")) throw new UserError("Use kw hook install|status|remove --global.");
        var directory = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(vault))!, "git-hooks");
        var metadata = Path.Combine(directory, "keywall-global.json");
        var current = Operations.GitText(".", "config", "--global", "--get", "--default", "", "core.hooksPath");
        var saved = File.Exists(metadata) ? JsonSerializer.Deserialize<GlobalManifest>(File.ReadAllText(metadata)) : null;
        bool configured = ShellPath(current).TrimEnd('/') .Equals(ShellPath(directory).TrimEnd('/'), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        bool intact = saved is not null && saved.Scripts.All(p => File.Exists(Path.Combine(directory, p.Key)) && File.ReadAllText(Path.Combine(directory, p.Key)) == p.Value);
        if (action == "status")
        {
            Console.WriteLine(configured && intact ? "Keywall global push guard enabled." : "Keywall global push guard absent, overridden or modified.");
            Console.WriteLine("Global hooks: " + directory);
            Console.WriteLine("Repository-local core.hooksPath and --no-verify can bypass the global guard."); return;
        }
        if (action == "remove")
        {
            if (!configured || !intact || saved is null) throw new UserError("Global config or managed hooks changed; refusing removal.");
            if (saved.PreviousGlobal.Length == 0) Operations.Git(".", "config", "--global", "--unset-all", "core.hooksPath");
            else Operations.Git(".", "config", "--global", "--replace-all", "core.hooksPath", saved.PreviousGlobal);
            foreach (var name in saved.Scripts.Keys) File.Delete(Path.Combine(directory, name));
            File.Delete(metadata);
            Console.WriteLine("Global guard removed; previous global hooks configuration restored."); return;
        }
        if (saved is not null)
        {
            if (!configured || !intact) throw new UserError("Global config or managed hooks changed; refusing overwrite.");
            Console.WriteLine("Keywall global push guard already enabled."); return;
        }
        if (Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any())
            throw new UserError("Global hooks directory already contains unmanaged files; refusing overwrite.");
        if (Directory.Exists(directory) && File.GetAttributes(directory).HasFlag(FileAttributes.ReparsePoint))
            throw new UserError("Global hooks directory cannot be a symbolic link.");
        if (configured) throw new UserError("Global hooks configuration points at an unmanaged Keywall directory.");
        // Resolve prior global path (including ~/ expansion), or preserve each repository's default hooks.
        var expanded = Operations.GitText(".", "config", "--global", "--path", "--get", "--default", "", "core.hooksPath");
        var setup = expanded.Length > 0 ? "previous=" + Quote(ShellPath(expanded)) + "\n" :
            "common=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || common=\"${GIT_DIR:-.git}\"\nprevious=\"$common/hooks\"\n";
        var scripts = new Dictionary<string, string>();
        foreach (var name in HookNames)
            scripts[name] = name == "pre-push" ? PushScript(Executable(), vault, setup, "\"$previous/pre-push\"") :
                "#!/bin/sh\n# Keywall forwards the original Git hook\n" + setup +
                "if [ -x \"$previous/" + name + "\" ]; then\n  exec \"$previous/" + name + "\" \"$@\"\nfi\nexit " + (name == "fsmonitor-watchman" ? "1" : "0") + "\n";
        Directory.CreateDirectory(directory);
        foreach (var entry in scripts) WriteHook(Path.Combine(directory, entry.Key), entry.Value);
        File.WriteAllText(metadata, JsonSerializer.Serialize(new GlobalManifest(current, scripts)), new UTF8Encoding(false));
        Operations.Git(".", "config", "--global", "--replace-all", "core.hooksPath", ShellPath(directory));
        Console.WriteLine("Keywall global push guard enabled for repositories that inherit global core.hooksPath.");
        Console.WriteLine("Original hooks are forwarded. Run kw login before pushing; local overrides and --no-verify can bypass checks.");
        Console.WriteLine("Global hooks: " + directory);
    }
    public static void Manage(string action, string repo, string vault)
    {
        if (action is not ("install" or "status" or "remove")) throw new UserError("Use kw hook install|status|remove [--repo PATH].");
        var common = Operations.GitText(repo, "rev-parse", "--path-format=absolute", "--git-common-dir");
        var custom = Operations.GitText(repo, "config", "--get", "--default", "", "core.hooksPath");
        if (custom.Length > 0)
            throw new UserError("core.hooksPath is configured. Automatic installation is refused to protect shared/managed hooks. Integrate kw git-check --stdin into that pre-push hook, or use kw push.");
        var directory = Path.Combine(common, "hooks");
        var hook = Path.Combine(directory, "pre-push");
        var original = Path.Combine(directory, "pre-push.keywall-original");
        var metadata = Path.Combine(directory, "pre-push.keywall.json");
        Manifest? saved = File.Exists(metadata) ? JsonSerializer.Deserialize<Manifest>(File.ReadAllText(metadata)) : null;
        bool intact = saved is not null && File.Exists(hook) && File.ReadAllText(hook) == saved.Script;
        if (action == "status")
        {
            Console.WriteLine(intact ? "Keywall pre-push hook enabled." : "Keywall pre-push hook absent or modified.");
            Console.WriteLine("Hook: " + hook); return;
        }
        if (action == "remove")
        {
            if (!intact || saved is null) throw new UserError("No intact managed hook; nothing removed.");
            if (saved.HadOriginal && !File.Exists(original)) throw new UserError("Original hook backup missing; nothing removed.");
            File.Delete(hook);
            if (saved.HadOriginal) File.Move(original, hook);
            File.Delete(metadata);
            Console.WriteLine("Keywall hook removed; previous hook restored."); return;
        }
        if (saved is not null)
        {
            if (!intact) throw new UserError("Managed hook changed; refusing to overwrite it.");
            Console.WriteLine("Keywall pre-push hook already enabled."); return;
        }
        if (File.Exists(original)) throw new UserError("Original-hook backup already exists; refusing to overwrite it.");
        Directory.CreateDirectory(directory);
        foreach (var file in new[] { directory, hook, metadata, original })
            if (Path.Exists(file) && File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint))
                throw new UserError("Hook installation refuses symbolic links.");
        var executable = Executable();
        bool hadOriginal = File.Exists(hook);
        // Buffer only Git ref/OID protocol data, so both guards receive identical stdin.
        var script = PushScript(executable, vault, "", hadOriginal ? Quote(ShellPath(original)) : "");
        if (hadOriginal) File.Move(hook, original);
        try
        {
            WriteHook(hook, script);
            File.WriteAllText(metadata, JsonSerializer.Serialize(new Manifest(script, hadOriginal)), new UTF8Encoding(false));
        }
        catch
        {
            File.Delete(hook); File.Delete(metadata);
            if (hadOriginal) File.Move(original, hook);
            throw;
        }
        Console.WriteLine("Keywall pre-push hook enabled. Ordinary git push is now checked in this repository.");
        Console.WriteLine("Unlock with kw login before pushing. Hook bypasses such as --no-verify remain possible.");
        Console.WriteLine("Hook: " + hook);
    }
}
