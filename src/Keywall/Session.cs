using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Keywall;

// Windows logon-session broker. Key material never enters an environment variable or disk cache.
public static class Session
{
    sealed record Bootstrap(string Path, string Salt, string Key);
    sealed record Request(string Action, string Salt);
    sealed record Response(string State, string? Key = null);
    static string PipeName(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new UserError("Session unlock currently requires Windows.");
        using var identity = WindowsIdentity.GetCurrent();
        var scope = Path.GetFullPath(path).ToUpperInvariant() + "|" + identity.User?.Value + "|" + Process.GetCurrentProcess().SessionId;
        return "keywall-session-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(scope)))[..40];
    }
    static Response? Send(string path, string action, string salt = "")
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName(path), PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            pipe.Connect(150);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, true);
            writer.WriteLine(JsonSerializer.Serialize(new Request(action, salt)));
            var reply = ReadLine(reader, 1024, timeout.Token).GetAwaiter().GetResult();
            return JsonSerializer.Deserialize<Response>(reply);
        }
        catch (Exception e) when (e is IOException or TimeoutException or OperationCanceledException or JsonException or UnauthorizedAccessException) { return null; }
    }
    public static bool IsUnlocked(string path) => Send(path, "status")?.State == "unlocked";
    public static bool Lock(string path) => Send(path, "lock")?.State == "locked";
    public static byte[]? GetKey(string path, string salt)
    {
        var response = Send(path, "get", salt);
        if (response?.State != "unlocked" || response.Key is null) return null;
        try { var key = Convert.FromBase64String(response.Key); return key.Length == 32 ? key : null; }
        catch (FormatException) { return null; }
    }
    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("SingleFile", "IL3000", Justification = "Assembly.Location is only read under the dotnet host; single-file apps launch Environment.ProcessPath directly.")]
    public static void Start(string path, string salt, byte[] key)
    {
        if (!OperatingSystem.IsWindows()) throw new UserError("Persistent session unlock currently requires Windows; use --no-session on other systems.");
        if (key.Length != 32) throw new UserError("Invalid session key.");
        Lock(path);
        string executable = Environment.ProcessPath ?? throw new UserError("Cannot locate session executable.");
        string commandLine = "\"" + executable + "\"";
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            commandLine += " \"" + typeof(Program).Assembly.Location + "\"";
        var bootstrapName = "keywall-bootstrap-" + Guid.NewGuid().ToString("N");
        commandLine += " _session " + bootstrapName;
        using var bootstrapPipe = new NamedPipeServerStream(bootstrapName, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
        // Inheriting ANY console/redirected handles keeps callers' output pipes open indefinitely.
        // CreateProcess(false) plus a private bootstrap pipe avoids inheriting those handles.
        var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>() };
        if (!CreateProcess(executable, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, false, 0x08000000,
            IntPtr.Zero, AppContext.BaseDirectory, ref startup, out var child)) throw new UserError("Cannot start unlock session.");
        CloseHandle(child.Thread);
        try
        {
            using var startupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            bootstrapPipe.WaitForConnectionAsync(startupTimeout.Token).GetAwaiter().GetResult();
            if (!GetNamedPipeClientProcessId(bootstrapPipe.SafePipeHandle.DangerousGetHandle(), out var clientPid) || clientPid != child.ProcessId)
                throw new UserError("Unexpected unlock bootstrap client.");
            using (var writer = new StreamWriter(bootstrapPipe, new UTF8Encoding(false), 1024, true) { AutoFlush = true })
                writer.WriteLine(JsonSerializer.Serialize(new Bootstrap(Path.GetFullPath(path), salt, Convert.ToBase64String(key))));
            for (int attempt = 0; attempt < 15; attempt++)
            {
                var fetched = GetKey(path, salt);
                if (fetched is not null)
                {
                    try { if (CryptographicOperations.FixedTimeEquals(fetched, key)) return; }
                    finally { CryptographicOperations.ZeroMemory(fetched); }
                }
                Thread.Sleep(50);
            }
            throw new UserError("Unlock session could not start; use --no-session to run without caching.");
        }
        catch { TerminateProcess(child.Process, 1); throw; }
        finally { CloseHandle(child.Process); }
    }
    public static async Task<int> Serve(string bootstrapName)
    {
        byte[]? key = null;
        try
        {
            if (!OperatingSystem.IsWindows()) return 1;
            if (!System.Text.RegularExpressions.Regex.IsMatch(bootstrapName, @"\Akeywall-bootstrap-[0-9a-f]{32}\z")) return 1;
            using var startupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var bootstrapPipe = new NamedPipeClientStream(".", bootstrapName, PipeDirection.In, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await bootstrapPipe.ConnectAsync(startupTimeout.Token);
            using var bootstrapReader = new StreamReader(bootstrapPipe, Encoding.UTF8, false, 1024, true);
            var bootstrap = JsonSerializer.Deserialize<Bootstrap>(await ReadLine(bootstrapReader, 16384, startupTimeout.Token));
            bootstrapPipe.Close();
            if (bootstrap is null || bootstrap.Salt.Length > 64) return 1;
            key = Convert.FromBase64String(bootstrap.Key);
            if (key.Length != 32 || Convert.FromBase64String(bootstrap.Salt).Length != 16) return 1;
            using var server = new NamedPipeServerStream(PipeName(bootstrap.Path), PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
            while (true)
            {
                await server.WaitForConnectionAsync();
                bool stop = false;
                try
                {
                    using var clientTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    using var reader = new StreamReader(server, Encoding.UTF8, false, 1024, true);
                    using var writer = new StreamWriter(server, new UTF8Encoding(false), 1024, true) { AutoFlush = true };
                    var request = JsonSerializer.Deserialize<Request>(await ReadLine(reader, 1024, clientTimeout.Token));
                    var response = new Response("locked");
                    if (request?.Action == "lock") stop = true;
                    else if (request?.Action == "status") response = new("unlocked");
                    else if (request?.Action == "get" && request.Salt == bootstrap.Salt) response = new("unlocked", Convert.ToBase64String(key));
                    await writer.WriteLineAsync(JsonSerializer.Serialize(response).AsMemory(), clientTimeout.Token);
                }
                catch (Exception e) when (e is IOException or OperationCanceledException or JsonException) { }
                finally { if (server.IsConnected) server.Disconnect(); }
                if (stop) return 0;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or FormatException or OperationCanceledException or UserError) { return 1; }
        finally { if (key is not null) CryptographicOperations.ZeroMemory(key); }
    }
    static async Task<string> ReadLine(TextReader reader, int limit, CancellationToken token)
    {
        var text = new StringBuilder(); var buffer = new char[1];
        while (await reader.ReadAsync(buffer.AsMemory(), token) > 0)
        {
            if (buffer[0] == '\n') return text.ToString().TrimEnd('\r');
            if (text.Length >= limit) throw new IOException("Session message exceeds limit.");
            text.Append(buffer[0]);
        }
        return text.ToString();
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo
    {
        public int Size; public IntPtr Reserved; public IntPtr Desktop; public IntPtr Title;
        public int X; public int Y; public int XSize; public int YSize; public int XCountChars; public int YCountChars;
        public int FillAttribute; public int Flags; public short ShowWindow; public short ReservedLength;
        public IntPtr ReservedPointer; public IntPtr Input; public IntPtr Output; public IntPtr Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo
    { public IntPtr Process; public IntPtr Thread; public uint ProcessId; public uint ThreadId; }
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processSecurity, IntPtr threadSecurity,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, int flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo process);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
}
