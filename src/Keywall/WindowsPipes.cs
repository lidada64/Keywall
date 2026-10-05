using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Keywall;

// .NET 8 CurrentUserOnly uses TokenOwner, which can change across Git's child
// processes even when TokenUser is identical. Use an explicit TokenUser DACL
// and authenticate both peers by their process token before exchanging keys.
[SupportedOSPlatform("windows")]
internal static class WindowsPipes
{
    public static NamedPipeServerStream CreateServer(string name, PipeDirection direction)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value ?? throw new UnauthorizedAccessException();
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("O:" + sid + "D:P(A;;GA;;;" + sid + ")", 1, out var descriptor, out _))
            throw new UnauthorizedAccessException("Cannot create user-only pipe permissions.");
        try
        {
            var attributes = new SecurityAttributes { Size = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
            // Overlapped I/O, first instance only, byte mode, reject remote clients.
            var handle = CreateNamedPipe("\\\\.\\pipe\\" + name, (uint)direction | 0x40000000 | 0x00080000,
                0x00000008, 1, 0, 0, 0, ref attributes);
            if (handle.IsInvalid) { handle.Dispose(); throw new IOException("Cannot create user-only pipe."); }
            try { return new NamedPipeServerStream(direction, true, false, handle); }
            catch { handle.Dispose(); throw; }
        }
        finally { LocalFree(descriptor); }
    }
    public static void ValidateServer(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid)) throw new UnauthorizedAccessException();
        ValidateProcess(pid);
    }
    public static void ValidateClient(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid)) throw new UnauthorizedAccessException();
        ValidateProcess(pid);
    }
    static void ValidateProcess(uint pid)
    {
        if (!ProcessIdToSessionId(pid, out var session) || session != Process.GetCurrentProcess().SessionId)
            throw new UnauthorizedAccessException("Pipe peer belongs to another Windows session.");
        using var process = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (process.IsInvalid || !OpenProcessToken(process, 0x0008, out var token)) throw new UnauthorizedAccessException();
        using (token)
        using (var peer = new WindowsIdentity(token.DangerousGetHandle()))
        using (var current = WindowsIdentity.GetCurrent())
            if (peer.User is null || current.User is null || !peer.User.Equals(current.User)) throw new UnauthorizedAccessException("Pipe peer belongs to another user.");
    }
    [StructLayout(LayoutKind.Sequential)]
    struct SecurityAttributes
    {
        public int Size; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }
    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string descriptor, uint revision, out IntPtr security, out uint size);
    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafePipeHandle CreateNamedPipe(string name, uint access, uint mode, uint instances, uint outputBuffer, uint inputBuffer, uint timeout, ref SecurityAttributes attributes);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ProcessIdToSessionId(uint pid, out uint session);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint pid);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
}
