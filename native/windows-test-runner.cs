using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

internal static class WindowsTestRunner
{
    const uint FileListDirectory = 1, FileShareRead = 1, FileShareWrite = 2, OpenExisting = 3, FileFlagBackupSemantics = 0x02000000, FileFlagOpenReparsePoint = 0x00200000, InvalidFileAttributes = 0xffffffff;
    const uint WaitObject0 = 0, WaitTimeout = 0x102, ProcessQueryLimitedInformation = 0x1000, Synchronize = 0x100000;
    const uint DosRawTargetPath = 1, DosRemoveDefinition = 2, DosExactMatchOnRemove = 4, DosNoBroadcast = 8;
    const int ProcThreadAttributeSecurityCapabilities = 0x20009, ProcThreadAttributeHandleList = 0x20002, ProcThreadAttributeJobList = 0x2000D, ProcThreadAttributeAllApplicationPackagesPolicy = 0x2000F;
    const uint AllApplicationPackagesPolicyLpac = 1, JobObjectExtendedLimitInformation = 9, JobObjectLimitKillOnJobClose = 0x2000, JobObjectLimitActiveProcess = 0x8, JobObjectLimitBreakawayOk = 0x800, JobObjectLimitSilentBreakawayOk = 0x1000;
    public sealed class Request
    {
        public string action;
        public string nonce;
        public string profile;
        public string cwd;
        public string runtime;
        public string scratch;
        public string executable;
        public string[] args;
        public int timeoutSeconds;
        public int maxFiles;
        public int maxOutputChars;
        public bool network;
        public bool childProcesses;
        public string stateDirectory;
        public string capabilityNonce;
        public int ownerPid;
        public Grant[] grants;
        public Dictionary<string, string> environment;
        public McpCustodyRequest mcpCustody;
    }

    public sealed class McpCustodyRequest
    {
        public string executionId;
        public string sha256;
        public long bytes;
    }

    public sealed class McpStagingWitness
    {
        public int version;
        public string executionId;
        public string copyDirectory;
        public string agentsDirectory;
        public string mcpConfigPath;
        public long? copyVolume;
        public long? copyFileIndexHigh;
        public long? copyFileIndexLow;
        public long? agentsVolume;
        public long? agentsFileIndexHigh;
        public long? agentsFileIndexLow;
        public long? volume;
        public long? fileIndexHigh;
        public long? fileIndexLow;
        public long? bytes;
        public string sha256;
    }

    public sealed class McpCustodyLease
    {
        public int version;
        public string executionId;
        public string sourcePath;
        public string agentsPath;
        public string custodyDirectory;
        public string custodyPath;
        public uint copyVolume;
        public uint copyFileIndexHigh;
        public uint copyFileIndexLow;
        public uint agentsVolume;
        public uint agentsFileIndexHigh;
        public uint agentsFileIndexLow;
        public uint custodyDirVolume;
        public uint custodyDirFileIndexHigh;
        public uint custodyDirFileIndexLow;
        public uint volume;
        public uint fileIndexHigh;
        public uint fileIndexLow;
        public long bytes;
        public string sha256;
        public string originalDaclBase64;
        public string originalDaclSha256;
        public string custodyDaclBase64;
        public string custodyDaclSha256;
    }

    sealed class McpCustodyHold : IDisposable
    {
        public McpCustodyLease lease;
        public IntPtr fileHandle = IntPtr.Zero;
        public IntPtr slotDirHandle = IntPtr.Zero;
        public IntPtr copyDirHandle = IntPtr.Zero;
        public IntPtr agentsDirHandle = IntPtr.Zero;
        public PinnedTarget copyPin;
        public PinnedTarget agentsPin;
        public void Dispose()
        {
            if (fileHandle != IntPtr.Zero && fileHandle != InvalidHandle) { CloseHandle(fileHandle); fileHandle = IntPtr.Zero; }
            if (slotDirHandle != IntPtr.Zero && slotDirHandle != InvalidHandle) { CloseHandle(slotDirHandle); slotDirHandle = IntPtr.Zero; }
            if (agentsDirHandle != IntPtr.Zero && agentsDirHandle != InvalidHandle) { CloseHandle(agentsDirHandle); agentsDirHandle = IntPtr.Zero; }
            if (copyDirHandle != IntPtr.Zero && copyDirHandle != InvalidHandle) { CloseHandle(copyDirHandle); copyDirHandle = IntPtr.Zero; }
            if (agentsPin != null) { agentsPin.Dispose(); agentsPin = null; }
            if (copyPin != null) { copyPin.Dispose(); copyPin = null; }
        }
    }

    public sealed class Grant
    {
        public string path;
        public string rights;
        public bool directory;
        public uint volume;
        public uint fileIndexHigh;
        public uint fileIndexLow;
    }

    public sealed class Lease
    {
        public int version;
        public string nonce;
        public string profile;
        public string sid;
        public string phase;
        public int controllerPid;
        public long controllerStarted;
        public int ownerPid;
        public long ownerStarted;
        public string cwd;
        public string runtime;
        public string scratch;
        public Grant[] grants;
        public string logon;
        public AliasPlan[] aliases;
        public bool nullDeviceGrant;
        public bool? jobCreated;
        public string capabilityNonce;
        public string readCapabilitySid;
        public string modifyCapabilitySid;
        public string nativeDaclSha256;
        public McpCustodyLease mcpCustody;
    }

    public sealed class WorkspaceLpacMeta
    {
        public int version;
        public string initializedAt;
        public string dev;
        public string ino;
        public string birthtimeNs;
        public string daclSha256;
        public string capabilityNonce;
        public string readCapabilitySid;
        public string modifyCapabilitySid;
        public long? volume;
        public long? fileIndexHigh;
        public long? fileIndexLow;
        public string nativeDaclSha256;
    }

    public sealed class WorkspaceMeta
    {
        public int version;
        public string sourceDirectory;
        public string rootKey;
        public string currentTaskId;
        public string currentLineageId;
        public string updatedAt;
        public double? lastPreparedDurationMs;
        public WorkspaceLpacMeta windowsLpac;
    }

    sealed class CanonicalWorkspaceInfo
    {
        public string copyPath;
        public string rootKey;
        public string metadataPath;
        public WorkspaceMeta meta;
        public Guid capabilityNonce;
        public SecurityIdentifier readSid;
        public SecurityIdentifier modifySid;
    }

    public sealed class AliasPlan
    {
        public string kind;
        public string physicalRoot;
        public string customName;
        public string drive;
        public string aliasRoot;
        public string customTarget;
        public string driveTarget;
        public uint volume;
        public uint fileIndexHigh;
        public uint fileIndexLow;
        internal DriveGate gate;
    }

    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int length; public IntPtr descriptor; public int inherit; }
    [StructLayout(LayoutKind.Sequential)] struct SecurityCapabilities { public IntPtr sid, capabilities; public uint count, reserved; }
    [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes { public IntPtr sid; public uint attributes; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct StartupInfo
    {
        public int cb; public string reserved, desktop, title;
        public uint x, y, xSize, ySize, xChars, yChars, fill, flags;
        public short showWindow, reservedSize; public IntPtr reservedBytes, input, output, error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx { public StartupInfo startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process, thread; public uint pid, threadId; }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits
    {
        public long processTime, jobTime; public uint flags; public UIntPtr minimumWorkingSet, maximumWorkingSet;
        public uint activeProcesses; public UIntPtr affinity; public uint priority, scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits { public BasicLimits basic; public IoCounters io; public UIntPtr processMemory, jobMemory, peakProcessMemory, peakJobMemory; }
    [StructLayout(LayoutKind.Sequential)] struct JobAccounting
    {
        public long totalUser, totalKernel, periodUser, periodKernel;
        public uint pageFaults, totalProcesses, activeProcesses, terminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint low, high; }
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint low; public int high; }
    [StructLayout(LayoutKind.Sequential)] struct TokenStatistics
    {
        public Luid tokenId, authenticationId; public long expiration; public uint tokenType, impersonationLevel, dynamicCharged, dynamicAvailable, groupCount, privilegeCount; public Luid modifiedId;
    }
    [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation
    {
        public uint attributes; public FileTime created, accessed, written; public uint volume, sizeHigh, sizeLow, links, indexHigh, indexLow;
    }

    sealed class PinnedTarget : IDisposable
    {
        public Grant grant;
        public int maxFiles;
        public bool revokeLeaf;
        readonly List<IntPtr> handles = new List<IntPtr>();
        public void Add(IntPtr value) { handles.Add(value); }
        public void Dispose() { for (int index = handles.Count - 1; index >= 0; index--) if (handles[index] != IntPtr.Zero) CloseHandle(handles[index]); handles.Clear(); }
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int CreateAppContainerProfile(string name, string display, string description, IntPtr capabilities, uint count, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int DeleteAppContainerProfile(string name);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool DeriveCapabilitySidsFromName(string name, out IntPtr groups, out uint groupCount, out IntPtr capabilities, out uint capabilityCount);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref UIntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, UIntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcess(string app, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string cwd, ref StartupInfoEx startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int info, IntPtr limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetKernelObjectSecurity(IntPtr handle, int securityInformation, byte[] pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetKernelObjectSecurity(IntPtr handle, int securityInformation, byte[] pSecurityDescriptor);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CreateMutex(IntPtr lpMutexAttributes, bool bInitialOwner, string lpName);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr OpenMutex(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReleaseMutex(IntPtr hMutex);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetFileSecurity(string path, uint information, byte[] descriptor, uint length, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SetFileSecurity(string path, uint information, byte[] descriptor);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr information, uint size, out uint returned);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFile(string name, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateDirectory(string pathName, IntPtr securityAttributes);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadFile(IntPtr handle, byte[] buffer, uint bytesToRead, out uint bytesRead, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetFilePointerEx(IntPtr handle, long distanceToMove, out long newFilePointer, uint moveMethod);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFinalPathNameByHandle(IntPtr handle, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetFileInformationByHandle(IntPtr handle, int fileInformationClass, IntPtr fileInformation, uint bufferSize);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(IntPtr handle, out ByHandleFileInformation info);
    [StructLayout(LayoutKind.Sequential)] struct FileAttributeTagInfo { public uint attributes, tag; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandleEx(IntPtr handle, int kind, out FileAttributeTagInfo info, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFileAttributes(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool DefineDosDevice(uint flags, string name, string target);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint QueryDosDevice(string name, char[] target, uint max);
    [DllImport("secur32.dll")] static extern int LsaEnumerateLogonSessions(out uint count, out IntPtr sessions);
    [DllImport("secur32.dll")] static extern int LsaFreeReturnBuffer(IntPtr buffer);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint desiredAccess, bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr job, int info, IntPtr limits, uint size, IntPtr returned);

    static readonly IntPtr InvalidHandle = new IntPtr(-1);

    static void Check(bool success, string operation)
    {
        if (!success) { int code = Marshal.GetLastWin32Error(); throw new Win32Exception(code, operation + " (Win32 " + code + "): " + new Win32Exception(code).Message); }
    }
    static void CheckHr(int result, string operation) { if (result < 0) throw new Exception(operation + ": 0x" + result.ToString("x8")); }
    static bool IsNotFoundHresult(int value) { return value == unchecked((int)0x80070002) || value == unchecked((int)0x80070003); }
    static long FileTimeValue(FileTime value) { return ((long)value.high << 32) | value.low; }

    sealed class ControllerIdentity
    {
        public SecurityIdentifier user;
        public string logon;
    }

    static ControllerIdentity CurrentControllerIdentity()
    {
        IntPtr token;
        Check(OpenProcessToken(Process.GetCurrentProcess().Handle, 8, out token), "Open controller token");
        try
        {
            uint returned;
            GetTokenInformation(token, 1, IntPtr.Zero, 0, out returned);
            if (returned < IntPtr.Size || returned > 65536) throw new Exception("Invalid controller user token size");
            IntPtr userData = Marshal.AllocHGlobal(checked((int)returned));
            try
            {
                Check(GetTokenInformation(token, 1, userData, returned, out returned), "Read controller user token");
                var user = new SecurityIdentifier(Marshal.ReadIntPtr(userData));
                if (user.IsWellKnown(WellKnownSidType.LocalSystemSid)) throw new Exception("LocalSystem cannot create local DOS aliases");
                int size = Marshal.SizeOf(typeof(TokenStatistics)); IntPtr statisticsData = Marshal.AllocHGlobal(size);
                try
                {
                    Check(GetTokenInformation(token, 10, statisticsData, (uint)size, out returned), "Read controller logon token");
                    var statistics = (TokenStatistics)Marshal.PtrToStructure(statisticsData, typeof(TokenStatistics));
                    return new ControllerIdentity { user = user, logon = ((uint)statistics.authenticationId.high).ToString("x8") + "." + statistics.authenticationId.low.ToString("x8") };
                }
                finally { Marshal.FreeHGlobal(statisticsData); }
            }
            finally { Marshal.FreeHGlobal(userData); }
        }
        finally { CloseHandle(token); }
    }

    static bool TryParseLogon(string value, out Luid logon)
    {
        logon = new Luid();
        if (String.IsNullOrEmpty(value) || value.Length != 17 || value[8] != '.') return false;
        for (int index = 0; index < value.Length; index++) if (index != 8 && !((value[index] >= '0' && value[index] <= '9') || (value[index] >= 'a' && value[index] <= 'f') || (value[index] >= 'A' && value[index] <= 'F'))) return false;
        uint high, low;
        if (!UInt32.TryParse(value.Substring(0, 8), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out high) || !UInt32.TryParse(value.Substring(9, 8), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out low)) return false;
        logon.high = unchecked((int)high); logon.low = low; return true;
    }

    // A drive letter is shared with runners built before the rename, which reserve it under the earlier name only.
    // Both mutexes are therefore taken, always in this order, so the two generations never define the same letter at once.
    static string[] DriveGateNames(string logon, char letter)
    {
        Luid parsed; if (!TryParseLogon(logon, out parsed)) throw new Exception("Invalid logon identifier for DOS alias mutex");
        return new string[] { "Global\\BLACK_GRAVITY.TEST.DOS." + logon + "." + letter, "Global\\AGY.TEST.DOS." + logon + "." + letter };
    }

    internal sealed class DriveGate
    {
        readonly Mutex current, earlier;
        internal DriveGate(Mutex current, Mutex earlier) { this.current = current; this.earlier = earlier; }
        internal void ReleaseMutex() { earlier.ReleaseMutex(); current.ReleaseMutex(); }
        internal void Close() { earlier.Close(); current.Close(); }
    }

    static bool LogonSessionExists(string value)
    {
        Luid expected; if (!TryParseLogon(value, out expected)) throw new Exception("Invalid logon identifier for DOS alias recovery");
        uint count; IntPtr sessions; int status = LsaEnumerateLogonSessions(out count, out sessions);
        if (status != 0) throw new Exception("Enumerate logon sessions: 0x" + status.ToString("x8"));
        try
        {
            if (count > 1048576) throw new Exception("Logon session enumeration exceeded its bounded count");
            int size = Marshal.SizeOf(typeof(Luid));
            for (uint index = 0; index < count; index++)
            {
                var candidate = (Luid)Marshal.PtrToStructure(IntPtr.Add(sessions, checked((int)(index * (uint)size))), typeof(Luid));
                if (candidate.high == expected.high && candidate.low == expected.low) return true;
            }
            return false;
        }
        finally
        {
            if (sessions != IntPtr.Zero)
            {
                int released = LsaFreeReturnBuffer(sessions);
                if (released != 0) throw new Exception("Free logon session enumeration: 0x" + released.ToString("x8"));
            }
        }
    }

    static string[] QueryDosTargets(string name)
    {
        for (uint capacity = 256; capacity <= 65536; capacity *= 2)
        {
            var buffer = new char[checked((int)capacity)];
            uint length = QueryDosDevice(name, buffer, capacity);
            if (length != 0) return new String(buffer, 0, checked((int)length)).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
            int error = Marshal.GetLastWin32Error();
            if (error == 2) return null;
            if (error == 122) continue;
            throw new Win32Exception(error, "Query DOS device " + name);
        }
        throw new Exception("DOS device query exceeded its bounded buffer");
    }

    static void RequireDosAbsent(string name)
    {
        string[] targets = QueryDosTargets(name);
        if (targets != null) throw new Exception("DOS device is already defined: " + name);
    }

    static void RequireDosExact(string name, string target)
    {
        string[] targets = QueryDosTargets(name);
        if (targets == null || targets.Length != 1 || !String.Equals(targets[0], target, StringComparison.Ordinal)) throw new Exception("DOS device definition is missing, foreign, or stacked: " + name);
    }

    static DriveGate AcquireDriveGate(char letter, ControllerIdentity controller)
    {
        var security = new MutexSecurity(); security.SetOwner(controller.user);
        security.AddAccessRule(new MutexAccessRule(controller.user, MutexRights.FullControl, AccessControlType.Allow));
        string[] names = DriveGateNames(controller.logon, letter);
        bool created; Mutex current = new Mutex(true, names[0], out created, security);
        if (!created) { current.Close(); return null; }
        Mutex earlier;
        try { earlier = new Mutex(true, names[1], out created, security); }
        catch { current.ReleaseMutex(); current.Close(); throw; }
        if (created) return new DriveGate(current, earlier);
        earlier.Close(); current.ReleaseMutex(); current.Close(); return null;
    }

    static DriveGate AcquireRecoveryDriveGate(char letter, ControllerIdentity controller, string logon)
    {
        var security = new MutexSecurity(); security.SetOwner(controller.user);
        security.AddAccessRule(new MutexAccessRule(controller.user, MutexRights.FullControl, AccessControlType.Allow));
        string[] names = DriveGateNames(logon, letter); var gates = new Mutex[names.Length]; int held = 0;
        try
        {
            for (int index = 0; index < names.Length; index++)
            {
                bool created, owned; gates[index] = new Mutex(false, names[index], out created, security);
                try { owned = gates[index].WaitOne(0); }
                catch (AbandonedMutexException) { owned = true; }
                if (!owned) throw new Exception("DOS drive mutex is held: " + letter);
                held = index + 1;
            }
            return new DriveGate(gates[0], gates[1]);
        }
        catch
        {
            for (int index = names.Length - 1; index >= 0; index--) if (gates[index] != null) { if (index < held) gates[index].ReleaseMutex(); gates[index].Close(); }
            throw;
        }
    }

    static string RawDosTarget(string value) { return "\\??\\" + value; }

    static AliasPlan[] CreateAliasPlan(Guid nonce, ControllerIdentity controller, PinnedTarget[] roots)
    {
        if (roots == null || roots.Length != 3) throw new Exception("Exactly three owned roots are required for DOS aliases");
        string[] kinds = new string[] { "copy", "runtime", "scratch" };
        var aliases = new AliasPlan[3]; int selected = 0;
        try
        {
            for (char letter = 'Z'; letter >= 'D' && selected < aliases.Length; letter--)
            {
                string drive = letter + ":"; if (QueryDosTargets(drive) != null) continue;
                DriveGate gate = AcquireDriveGate(letter, controller); if (gate == null) continue;
                try
                {
                    if (QueryDosTargets(drive) != null) continue;
                    Grant root = roots[selected].grant;
                    if (!root.directory) throw new Exception("Owned DOS alias root is not a directory");
                    string custom = "BLACK_GRAVITY.TEST." + nonce.ToString("D").ToUpperInvariant() + "." + kinds[selected].ToUpperInvariant();
                    RequireDosAbsent(custom);
                    aliases[selected] = new AliasPlan { kind = kinds[selected], physicalRoot = root.path, customName = custom, drive = drive, aliasRoot = drive + "\\", customTarget = RawDosTarget(root.path), driveTarget = RawDosTarget(custom), volume = root.volume, fileIndexHigh = root.fileIndexHigh, fileIndexLow = root.fileIndexLow, gate = gate };
                    gate = null; selected++;
                }
                finally { if (gate != null) { gate.ReleaseMutex(); gate.Close(); } }
            }
            if (selected != aliases.Length) throw new Exception("Fewer than three unused DOS drive letters are available");
            return aliases;
        }
        catch { ReleaseAliasGates(aliases); throw; }
    }

    static void ReleaseAliasGates(AliasPlan[] aliases)
    {
        if (aliases == null) return;
        for (int index = aliases.Length - 1; index >= 0; index--) if (aliases[index] != null && aliases[index].gate != null)
        {
            aliases[index].gate.ReleaseMutex(); aliases[index].gate.Close(); aliases[index].gate = null;
        }
    }

    static void AcquireRecoveryAliasGates(AliasPlan[] aliases, ControllerIdentity controller, string logon)
    {
        try
        {
            for (int index = 0; index < aliases.Length; index++) aliases[index].gate = AcquireRecoveryDriveGate(aliases[index].drive[0], controller, logon);
        }
        catch { ReleaseAliasGates(aliases); throw; }
    }

    static void VerifyAliasRoot(AliasPlan alias)
    {
        IntPtr handle = CreateFile(alias.aliasRoot, 0, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == InvalidHandle) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open DOS alias root");
        try
        {
            ByHandleFileInformation info; Check(GetFileInformationByHandle(handle, out info), "Inspect DOS alias root");
            if ((info.attributes & (uint)FileAttributes.ReparsePoint) != 0 || (info.attributes & (uint)FileAttributes.Directory) == 0 || info.volume != alias.volume || info.indexHigh != alias.fileIndexHigh || info.indexLow != alias.fileIndexLow) throw new Exception("DOS alias root identity changed");
        }
        finally { CloseHandle(handle); }
    }

    static void DefineAlias(AliasPlan alias, bool drive)
    {
        string name = drive ? alias.drive : alias.customName, target = drive ? alias.driveTarget : alias.customTarget;
        RequireDosAbsent(name); Check(DefineDosDevice(DosRawTargetPath | DosNoBroadcast, name, target), "Define DOS device " + name); RequireDosExact(name, target);
    }

    static void ApplyAliases(AliasPlan[] aliases)
    {
        for (int index = 0; index < aliases.Length; index++) DefineAlias(aliases[index], false);
        for (int index = 0; index < aliases.Length; index++) DefineAlias(aliases[index], true);
        for (int index = 0; index < aliases.Length; index++) { RequireDosExact(aliases[index].customName, aliases[index].customTarget); RequireDosExact(aliases[index].drive, aliases[index].driveTarget); VerifyAliasRoot(aliases[index]); }
    }

    static void RemoveAlias(AliasPlan alias, bool drive)
    {
        string name = drive ? alias.drive : alias.customName, target = drive ? alias.driveTarget : alias.customTarget;
        string[] current = QueryDosTargets(name); if (current == null) return;
        if (current.Length != 1 || !String.Equals(current[0], target, StringComparison.Ordinal)) throw new Exception("DOS alias cleanup found a foreign or stacked definition: " + name);
        Check(DefineDosDevice(DosRawTargetPath | DosNoBroadcast | DosRemoveDefinition | DosExactMatchOnRemove, name, target), "Remove DOS device " + name);
        if (QueryDosTargets(name) != null) throw new Exception("DOS alias remained after exact cleanup: " + name);
    }

    static void RemoveAliases(AliasPlan[] aliases)
    {
        if (aliases == null) return;
        var failures = new List<string>();
        for (int index = aliases.Length - 1; index >= 0; index--) try { RemoveAlias(aliases[index], true); } catch (Exception error) { failures.Add(error.Message); }
        for (int index = aliases.Length - 1; index >= 0; index--) try { RemoveAlias(aliases[index], false); } catch (Exception error) { failures.Add(error.Message); }
        if (failures.Count != 0) throw new Exception(String.Join("; ", failures.ToArray()));
    }

    static bool IsPhysicalAbsolutePath(string value)
    {
        return !String.IsNullOrEmpty(value) && value.Length >= 3 && Char.IsLetter(value[0]) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') && !value.StartsWith("\\\\", StringComparison.Ordinal) && value.IndexOf(':', 2) < 0;
    }

    static string ProjectOwnedPath(string value, AliasPlan[] aliases)
    {
        if (!IsPhysicalAbsolutePath(value)) return value;
        for (int index = 0; index < aliases.Length; index++)
        {
            string root = aliases[index].physicalRoot;
            if (value.Length < root.Length) continue;
            bool match = true;
            for (int character = 0; character < root.Length; character++)
            {
                char actual = value[character], expected = root[character];
                if ((actual == '\\' || actual == '/') && (expected == '\\' || expected == '/')) continue;
                if (Char.ToUpperInvariant(actual) != Char.ToUpperInvariant(expected)) { match = false; break; }
            }
            if (!match || (value.Length > root.Length && value[root.Length] != '\\' && value[root.Length] != '/')) continue;
            string tail = value.Substring(root.Length).TrimStart('\\', '/');
            foreach (string part in tail.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries)) if (part == "." || part == "..") return value;
            return aliases[index].aliasRoot + tail.Replace('/', '\\');
        }
        return value;
    }

    static string[] ProjectArguments(string[] arguments, AliasPlan[] aliases)
    {
        var projected = new string[arguments.Length]; for (int index = 0; index < arguments.Length; index++) projected[index] = ProjectOwnedPath(arguments[index], aliases); return projected;
    }

    static Dictionary<string, string> ProjectEnvironment(Request request, AliasPlan[] aliases)
    {
        string systemRoot = Environment.GetEnvironmentVariable("SystemRoot"); RequireLocalAbsolutePath(systemRoot, "SystemRoot");
        string system32 = Path.Combine(systemRoot, "System32");
        string system32Canonical = Path.GetFullPath(system32);
        var projected = new Dictionary<string, string>(request.environment, StringComparer.OrdinalIgnoreCase);
        AliasPlan runtime = aliases[1], scratch = aliases[2];

        string runtimePhysical = Path.GetFullPath(runtime.physicalRoot);
        string runtimeSeparator = runtimePhysical.EndsWith("\\") ? runtimePhysical : runtimePhysical + "\\";

        var pathEntries = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        pathEntries.Add(runtime.aliasRoot);
        seen.Add(runtime.aliasRoot);

        string rawPath;
        if (projected.TryGetValue("PATH", out rawPath) && !String.IsNullOrEmpty(rawPath))
        {
            string[] items = rawPath.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string rawItem in items)
            {
                string item = rawItem.Trim().Trim('"');
                if (String.IsNullOrEmpty(item)) continue;
                if (!IsPhysicalAbsolutePath(item)) continue;
                string full;
                try { full = Path.GetFullPath(item); } catch { continue; }
                if (!IsPhysicalAbsolutePath(full)) continue;

                if (String.Equals(full, system32Canonical, StringComparison.OrdinalIgnoreCase)) continue;

                bool isRuntimeOwned = String.Equals(full, runtimePhysical, StringComparison.OrdinalIgnoreCase) ||
                                      full.StartsWith(runtimeSeparator, StringComparison.OrdinalIgnoreCase);
                if (!isRuntimeOwned) continue;

                string mapped = ProjectOwnedPath(full, aliases);
                if (!mapped.StartsWith(runtime.aliasRoot, StringComparison.OrdinalIgnoreCase)) continue;

                if (seen.Add(mapped))
                {
                    pathEntries.Add(mapped);
                }
            }
        }

        if (seen.Add(system32))
        {
            pathEntries.Add(system32);
        }

        projected["PATH"] = String.Join(";", pathEntries.ToArray());
        foreach (string key in new string[] { "TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA" }) projected[key] = scratch.aliasRoot;
        string comspec; if (!projected.TryGetValue("COMSPEC", out comspec)) comspec = Path.Combine(systemRoot, "System32", "cmd.exe"); projected["COMSPEC"] = ProjectOwnedPath(comspec, aliases);

        string gitExecPath;
        if (projected.TryGetValue("GIT_EXEC_PATH", out gitExecPath) && !String.IsNullOrEmpty(gitExecPath))
        {
            RequireLocalAbsolutePath(gitExecPath, "GIT_EXEC_PATH");
            string fullGitExec = Path.GetFullPath(gitExecPath);
            RequireLocalAbsolutePath(fullGitExec, "GIT_EXEC_PATH");
            bool isInsideRuntime = String.Equals(fullGitExec, runtimePhysical, StringComparison.OrdinalIgnoreCase) ||
                                  fullGitExec.StartsWith(runtimeSeparator, StringComparison.OrdinalIgnoreCase);
            if (!isInsideRuntime) throw new Exception("GIT_EXEC_PATH must be located inside the runtime directory: " + gitExecPath);
            string projectedGitExec = ProjectOwnedPath(fullGitExec, aliases);
            if (!projectedGitExec.StartsWith(runtime.aliasRoot, StringComparison.OrdinalIgnoreCase)) throw new Exception("GIT_EXEC_PATH projection failed: " + gitExecPath);
            projected["GIT_EXEC_PATH"] = projectedGitExec;

            var poisonKeys = new List<string>();
            foreach (string envKey in projected.Keys)
            {
                if (String.Equals(envKey, "GIT_CONFIG_COUNT", StringComparison.OrdinalIgnoreCase) ||
                    String.Equals(envKey, "GIT_CONFIG_PARAMETERS", StringComparison.OrdinalIgnoreCase) ||
                    envKey.StartsWith("GIT_CONFIG_KEY_", StringComparison.OrdinalIgnoreCase) ||
                    envKey.StartsWith("GIT_CONFIG_VALUE_", StringComparison.OrdinalIgnoreCase))
                {
                    poisonKeys.Add(envKey);
                }
            }
            foreach (string poisonKey in poisonKeys)
            {
                projected.Remove(poisonKey);
            }

            AliasPlan copyAlias = aliases[0];
            string copyAliasRoot = copyAlias.aliasRoot;
            var safeDirectories = new List<string>();
            safeDirectories.Add("");
            safeDirectories.Add(copyAliasRoot);

            int copyMaxFiles = request.maxFiles;
            if (copyMaxFiles < 1) throw new Exception("Invalid repository discovery file limit");
            string copyPhysicalRoot = Path.GetFullPath(copyAlias.physicalRoot);
            var nestedRepos = new List<string>();
            DiscoverNestedGitRepositories(copyPhysicalRoot, copyPhysicalRoot, copyMaxFiles, new int[] { 0 }, nestedRepos);
            nestedRepos.Sort(StringComparer.OrdinalIgnoreCase);
            foreach (string nestedRepo in nestedRepos)
            {
                string projectedNested = ProjectOwnedPath(nestedRepo, aliases);
                if (projectedNested.StartsWith(copyAliasRoot, StringComparison.OrdinalIgnoreCase) && !safeDirectories.Contains(projectedNested))
                {
                    safeDirectories.Add(projectedNested);
                }
            }

            projected["GIT_CONFIG_COUNT"] = safeDirectories.Count.ToString();
            for (int index = 0; index < safeDirectories.Count; index++)
            {
                projected["GIT_CONFIG_KEY_" + index.ToString()] = "safe.directory";
                projected["GIT_CONFIG_VALUE_" + index.ToString()] = safeDirectories[index];
            }
        }

        string gitConfigGlobal;
        if (projected.TryGetValue("GIT_CONFIG_GLOBAL", out gitConfigGlobal) && !String.IsNullOrEmpty(gitConfigGlobal))
        {
            RequireLocalAbsolutePath(gitConfigGlobal, "GIT_CONFIG_GLOBAL");
            string fullGitConfig = Path.GetFullPath(gitConfigGlobal);
            RequireLocalAbsolutePath(fullGitConfig, "GIT_CONFIG_GLOBAL");
            string scratchPhysical = Path.GetFullPath(scratch.physicalRoot);
            string scratchSeparator = scratchPhysical.EndsWith("\\") ? scratchPhysical : scratchPhysical + "\\";
            bool isInsideScratch = String.Equals(fullGitConfig, scratchPhysical, StringComparison.OrdinalIgnoreCase) ||
                                  fullGitConfig.StartsWith(scratchSeparator, StringComparison.OrdinalIgnoreCase);
            if (!isInsideScratch) throw new Exception("GIT_CONFIG_GLOBAL must be located inside the scratch directory: " + gitConfigGlobal);
            string projectedGitConfig = ProjectOwnedPath(fullGitConfig, aliases);
            if (!projectedGitConfig.StartsWith(scratch.aliasRoot, StringComparison.OrdinalIgnoreCase)) throw new Exception("GIT_CONFIG_GLOBAL projection failed: " + gitConfigGlobal);
            projected["GIT_CONFIG_GLOBAL"] = projectedGitConfig;
        }

        return projected;
    }

    static List<Dictionary<string, string>> PathMappings(AliasPlan[] aliases)
    {
        var mappings = new List<Dictionary<string, string>>(); foreach (AliasPlan alias in aliases) mappings.Add(new Dictionary<string, string> { { "kind", alias.kind }, { "aliasRoot", alias.aliasRoot }, { "physicalRoot", alias.physicalRoot } }); return mappings;
    }

    static void RequireLocalAbsolutePath(string value, string description)
    {
        if (String.IsNullOrEmpty(value) || value.IndexOf('\0') >= 0 || value.StartsWith("\\\\", StringComparison.Ordinal) || value.StartsWith("//", StringComparison.Ordinal) ||
            value.StartsWith("\\\\?\\", StringComparison.Ordinal) || value.StartsWith("\\\\.\\", StringComparison.Ordinal) || value.Length < 3 ||
            !Char.IsLetter(value[0]) || value[1] != ':' || (value[2] != '\\' && value[2] != '/')) throw new Exception(description + " must be a local absolute path");
        if (value.IndexOf(':', 2) >= 0) throw new Exception(description + " cannot use an alternate data stream");
    }

    static string OwnedTemporaryPath(string directory, string prefix)
    {
        RequireLocalAbsolutePath(directory, "Directory");
        string full = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
        string parent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetDirectoryName(full), parent, StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(full).StartsWith(prefix, StringComparison.Ordinal)) throw new Exception("Directory is not owned temporary storage");
        return full;
    }

    // A copy persisted before the rename keeps its original name until it is discarded.
    static string CopyPrefix(string directory)
    {
        return directory != null && Path.GetFileName(directory.TrimEnd(Path.DirectorySeparatorChar)).StartsWith("agy-mcp-copy-", StringComparison.Ordinal) ? "agy-mcp-copy-" : "black-gravity-copy-";
    }

    static string OwnedDirectory(string directory, string prefix)
    {
        string full = OwnedTemporaryPath(directory, prefix);
        if (!Directory.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new Exception("Directory was replaced or linked");
        return full;
    }

    static string StateLeaseDirectory(string stateDirectory)
    {
        RequireLocalAbsolutePath(stateDirectory, "State directory");
        string state = Path.GetFullPath(stateDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (!Directory.Exists(state) || (File.GetAttributes(state) & FileAttributes.ReparsePoint) != 0) throw new Exception("State directory is unavailable or linked");
        string lease = Path.Combine(state, "windows-lpac-leases");
        if (!Directory.Exists(lease)) Directory.CreateDirectory(lease);
        if ((File.GetAttributes(lease) & FileAttributes.ReparsePoint) != 0) throw new Exception("Lease directory is linked");
        return lease;
    }

    static bool IsLowerHex(string value, int length)
    {
        if (String.IsNullOrEmpty(value) || value.Length != length) return false;
        for (int index = 0; index < value.Length; index++)
        {
            char ch = value[index];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
        }
        return true;
    }

    static string ComputeSha256Hex(byte[] data)
    {
        using (SHA256 sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(data);
            var sb = new StringBuilder(hash.Length * 2);
            for (int index = 0; index < hash.Length; index++) sb.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
    }

    static string ComputeWorkspaceRootKey(string sourceDirectory)
    {
        RequireLocalAbsolutePath(sourceDirectory, "Workspace source directory");
        string resolved = Path.GetFullPath(sourceDirectory);
        if (resolved.Length > 3) resolved = resolved.TrimEnd(Path.DirectorySeparatorChar);
        byte[] bytes = Encoding.UTF8.GetBytes(resolved.ToLowerInvariant());
        return ComputeSha256Hex(bytes).Substring(0, 32);
    }

    static bool OverlapsPath(string left, string right)
    {
        if (String.IsNullOrEmpty(left) || String.IsNullOrEmpty(right)) return false;
        string a = Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string b = Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (String.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
        string aPrefix = a.EndsWith("\\", StringComparison.Ordinal) ? a : a + "\\";
        string bPrefix = b.EndsWith("\\", StringComparison.Ordinal) ? b : b + "\\";
        return b.StartsWith(aPrefix, StringComparison.OrdinalIgnoreCase) || a.StartsWith(bPrefix, StringComparison.OrdinalIgnoreCase);
    }

    static bool TryGetCanonicalWorkspaceRootKey(string directory, string stateDirectory, out string fullCopy, out string rootKey, out string metadataPath)
    {
        fullCopy = null; rootKey = null; metadataPath = null;
        if (String.IsNullOrEmpty(directory) || String.IsNullOrEmpty(stateDirectory)) return false;
        try
        {
            RequireLocalAbsolutePath(directory, "Workspace copy directory");
            RequireLocalAbsolutePath(stateDirectory, "State directory");
        }
        catch { return false; }
        string copy = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
        string state = Path.GetFullPath(stateDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(Path.GetFileName(copy), "copy", StringComparison.OrdinalIgnoreCase)) return false;
        string workspaceDir = Path.GetDirectoryName(copy);
        if (String.IsNullOrEmpty(workspaceDir)) return false;
        string key = Path.GetFileName(workspaceDir);
        if (!IsLowerHex(key, 32)) return false;
        string workspacesDir = Path.GetDirectoryName(workspaceDir);
        if (String.IsNullOrEmpty(workspacesDir) || !String.Equals(Path.GetFileName(workspacesDir), "workspaces", StringComparison.OrdinalIgnoreCase)) return false;
        string parentState = Path.GetDirectoryName(workspacesDir);
        if (String.IsNullOrEmpty(parentState) || !String.Equals(parentState.TrimEnd(Path.DirectorySeparatorChar), state, StringComparison.OrdinalIgnoreCase)) return false;
        fullCopy = copy;
        rootKey = key;
        metadataPath = Path.Combine(workspaceDir, "workspace.json");
        return true;
    }

    static string WorkspaceCapabilityName(string rootKey, Guid capabilityNonce, bool modify)
    {
        return "blackGravityWorkspace" + rootKey + capabilityNonce.ToString("N") + (modify ? "Modify" : "Read");
    }

    static SecurityIdentifier DeriveNamedCapabilitySid(string name)
    {
        var allocations = new List<IntPtr>();
        try
        {
            IntPtr sidPtr = DeriveCapability(name, allocations);
            var sid = new SecurityIdentifier(sidPtr);
            if (!IsNamedCapabilitySid(sid)) throw new Exception("Derived capability SID has unexpected authority");
            return sid;
        }
        finally
        {
            foreach (IntPtr ptr in allocations) if (ptr != IntPtr.Zero) LocalFree(ptr);
        }
    }

    static bool IsAppContainerPackageSid(SecurityIdentifier sid)
    {
        return sid != null && sid.Value.StartsWith("S-1-15-2-", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsNamedCapabilitySid(SecurityIdentifier sid)
    {
        return sid != null && sid.Value.StartsWith("S-1-15-3-1024-", StringComparison.OrdinalIgnoreCase);
    }

    static string DaclSha256(RawSecurityDescriptor descriptor)
    {
        if (descriptor == null || descriptor.DiscretionaryAcl == null) throw new Exception("Target has no DACL");
        byte[] flagBytes = BitConverter.GetBytes((int)descriptor.ControlFlags);
        byte[] aclBytes = new byte[descriptor.DiscretionaryAcl.BinaryLength];
        descriptor.DiscretionaryAcl.GetBinaryForm(aclBytes, 0);
        byte[] combined = new byte[flagBytes.Length + aclBytes.Length];
        Buffer.BlockCopy(flagBytes, 0, combined, 0, flagBytes.Length);
        Buffer.BlockCopy(aclBytes, 0, combined, flagBytes.Length, aclBytes.Length);
        return ComputeSha256Hex(combined);
    }

    static CanonicalWorkspaceInfo ValidateCanonicalWorkspaceCopy(string cwd, string stateDirectory, JavaScriptSerializer serializer, bool requireInitialized)
    {
        string fullCopy, rootKey, metadataPath;
        if (!TryGetCanonicalWorkspaceRootKey(cwd, stateDirectory, out fullCopy, out rootKey, out metadataPath))
        {
            throw new Exception("Directory is not an owned canonical workspace copy");
        }
        if (!Directory.Exists(fullCopy) || (File.GetAttributes(fullCopy) & FileAttributes.ReparsePoint) != 0)
        {
            throw new Exception("Canonical workspace copy directory is unavailable or linked");
        }
        if (!File.Exists(metadataPath) || (File.GetAttributes(metadataPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new Exception("Canonical workspace metadata is missing or linked");
        }
        var metaInfo = new FileInfo(metadataPath);
        if (metaInfo.Length <= 0 || metaInfo.Length > 1024 * 1024) throw new Exception("Canonical workspace metadata size is invalid");
        WorkspaceMeta meta = serializer.Deserialize<WorkspaceMeta>(File.ReadAllText(metadataPath, Encoding.UTF8));
        if (meta == null || meta.version != 1 || String.IsNullOrEmpty(meta.sourceDirectory) || !String.Equals(meta.rootKey, rootKey, StringComparison.Ordinal))
        {
            throw new Exception("Canonical workspace metadata identity mismatch");
        }
        if (!String.Equals(ComputeWorkspaceRootKey(meta.sourceDirectory), rootKey, StringComparison.Ordinal))
        {
            throw new Exception("Canonical workspace rootKey does not match sourceDirectory");
        }
        var info = new CanonicalWorkspaceInfo { copyPath = fullCopy, rootKey = rootKey, metadataPath = metadataPath, meta = meta };
        if (requireInitialized)
        {
            if (meta.windowsLpac == null || meta.windowsLpac.version != 1) throw new Exception("Canonical workspace LPAC permissions are not initialized");
            Guid capNonce;
            if (String.IsNullOrEmpty(meta.windowsLpac.capabilityNonce) || !Guid.TryParseExact(meta.windowsLpac.capabilityNonce, "D", out capNonce))
            {
                throw new Exception("Canonical workspace LPAC capability nonce is missing or invalid");
            }
            if (!meta.windowsLpac.volume.HasValue || !meta.windowsLpac.fileIndexHigh.HasValue || !meta.windowsLpac.fileIndexLow.HasValue ||
                meta.windowsLpac.volume.Value < 0 || meta.windowsLpac.volume.Value > UInt32.MaxValue ||
                meta.windowsLpac.fileIndexHigh.Value < 0 || meta.windowsLpac.fileIndexHigh.Value > UInt32.MaxValue ||
                meta.windowsLpac.fileIndexLow.Value < 0 || meta.windowsLpac.fileIndexLow.Value > UInt32.MaxValue)
            {
                throw new Exception("Canonical workspace LPAC folder identity is missing or invalid");
            }
            if (!IsLowerHex(meta.windowsLpac.nativeDaclSha256, 64))
            {
                throw new Exception("Canonical workspace LPAC DACL digest is missing or invalid");
            }
            SecurityIdentifier expectedRead = DeriveNamedCapabilitySid(WorkspaceCapabilityName(rootKey, capNonce, false));
            SecurityIdentifier expectedModify = DeriveNamedCapabilitySid(WorkspaceCapabilityName(rootKey, capNonce, true));
            if (String.IsNullOrEmpty(meta.windowsLpac.readCapabilitySid) || String.IsNullOrEmpty(meta.windowsLpac.modifyCapabilitySid) ||
                !expectedRead.Equals(new SecurityIdentifier(meta.windowsLpac.readCapabilitySid)) ||
                !expectedModify.Equals(new SecurityIdentifier(meta.windowsLpac.modifyCapabilitySid)) ||
                expectedRead.Equals(expectedModify))
            {
                throw new Exception("Canonical workspace LPAC capability SID mismatch");
            }
            info.capabilityNonce = capNonce;
            info.readSid = expectedRead;
            info.modifySid = expectedModify;
        }
        return info;
    }

    static string ValidateCanonicalWorkspaceDacl(
        PinnedTarget rootPin,
        SecurityIdentifier allowedRead,
        SecurityIdentifier allowedModify,
        string expectedNativeDaclSha256,
        bool requireBoth,
        int maxFiles)
    {
        RawSecurityDescriptor rootDescriptor = ReadDacl(rootPin.grant.path);
        string actualDigest = DaclSha256(rootDescriptor);
        if (expectedNativeDaclSha256 != null && !String.Equals(actualDigest, expectedNativeDaclSha256, StringComparison.Ordinal))
        {
            throw new Exception("Canonical workspace folder DACL changed since LPAC baseline was pinned");
        }
        CheckWorkspaceEntryDacl(rootDescriptor, true, true, allowedRead, allowedModify, requireBoth);
        ValidateCanonicalWorkspaceChildren(rootPin.grant.path, allowedRead, allowedModify, requireBoth, maxFiles, new int[] { 0 });
        return actualDigest;
    }

    static void CheckWorkspaceEntryDacl(
        RawSecurityDescriptor descriptor,
        bool isRoot,
        bool isDirectory,
        SecurityIdentifier allowedRead,
        SecurityIdentifier allowedModify,
        bool requireBoth)
    {
        if (descriptor == null || descriptor.DiscretionaryAcl == null) throw new Exception("Canonical workspace entry has no DACL");
        if (!isRoot && (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0)
        {
            throw new Exception("Canonical workspace descendant has a protected DACL");
        }
        int expectedReadMask = (int)(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize);
        int expectedModifyMask = (int)(FileSystemRights.Modify | FileSystemRights.Synchronize);
        AceFlags inheritBoth = AceFlags.ContainerInherit | AceFlags.ObjectInherit;
        int readMatches = 0, modifyMatches = 0;
        RawAcl acl = descriptor.DiscretionaryAcl;
        for (int index = 0; index < acl.Count; index++)
        {
            KnownAce known = acl[index] as KnownAce;
            if (known == null) continue;
            if (IsAppContainerPackageSid(known.SecurityIdentifier))
            {
                throw new Exception("Canonical workspace contains forbidden AppContainer package ACE");
            }
            if (!IsNamedCapabilitySid(known.SecurityIdentifier)) continue;
            CommonAce common = known as CommonAce;
            if (allowedRead != null && allowedRead.Equals(known.SecurityIdentifier))
            {
                if (common == null || common.AceQualifier != AceQualifier.AccessAllowed || common.IsCallback ||
                    common.AccessMask != expectedReadMask || (common.AceFlags & AceFlags.InheritOnly) != 0 ||
                    (isRoot && common.AceFlags != inheritBoth) ||
                    (!isRoot && isDirectory && (common.AceFlags & inheritBoth) != inheritBoth))
                {
                    throw new Exception("Canonical workspace read capability ACE was altered");
                }
                readMatches++;
            }
            else if (allowedModify != null && allowedModify.Equals(known.SecurityIdentifier))
            {
                if (common == null || common.AceQualifier != AceQualifier.AccessAllowed || common.IsCallback ||
                    common.AccessMask != expectedModifyMask || (common.AceFlags & AceFlags.InheritOnly) != 0 ||
                    (isRoot && common.AceFlags != inheritBoth) ||
                    (!isRoot && isDirectory && (common.AceFlags & inheritBoth) != inheritBoth))
                {
                    throw new Exception("Canonical workspace modify capability ACE was altered");
                }
                modifyMatches++;
            }
            else
            {
                throw new Exception("Canonical workspace contains unexpected capability ACE");
            }
        }
        if (requireBoth && (readMatches != 1 || modifyMatches != 1))
        {
            throw new Exception("Canonical workspace scoped LPAC capability ACEs are missing or duplicated");
        }
        if (!requireBoth && (readMatches != 0 || modifyMatches != 0))
        {
            throw new Exception("Canonical workspace already contains LPAC capability ACEs");
        }
    }

    static void ValidateCanonicalWorkspaceChildren(
        string directory,
        SecurityIdentifier allowedRead,
        SecurityIdentifier allowedModify,
        bool requireBoth,
        int maxFiles,
        int[] count)
    {
        foreach (string child in Directory.EnumerateFileSystemEntries(directory))
        {
            if (++count[0] > maxFiles) throw new Exception("Canonical workspace exceeds the configured file limit");
            using (var pin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = maxFiles })
            {
                ValidatePathComponents(child, pin, false, maxFiles);
                CheckWorkspaceEntryDacl(ReadDacl(pin.grant.path), false, pin.grant.directory, allowedRead, allowedModify, requireBoth);
                if (pin.grant.directory)
                {
                    ValidateCanonicalWorkspaceChildren(pin.grant.path, allowedRead, allowedModify, requireBoth, maxFiles, count);
                }
            }
        }
    }

    const int MaxMcpConfigBytes = 1024 * 1024;
    const uint FileReadData = 0x00000001;
    const uint FileReadAttributes = 0x00000080;
    const uint DeleteAccess = 0x00010000;
    const uint RequiredCustodyFileAccess = FileReadData | FileReadAttributes | DeleteAccess | StandardRightsRead | StandardRightsWriteDac | Synchronize;

    static bool IsInitLeaseVersion(int version) { return version == 4 || version == 6; }
    static bool IsRunLeaseWithJobVersion(int version) { return version == 3 || version == 5; }

    static string CanonicalLocalPath(string value, string description)
    {
        RequireLocalAbsolutePath(value, description);
        string full = Path.GetFullPath(value);
        if (full.Length > 3) full = full.TrimEnd(Path.DirectorySeparatorChar);
        return full;
    }

    static bool IsValidUint32(long? value)
    {
        return value.HasValue && value.Value >= 0 && value.Value <= UInt32.MaxValue;
    }

    static string FinalPathByHandle(IntPtr handle)
    {
        var sb = new StringBuilder(260);
        uint length = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, 0);
        if (length == 0) Check(false, "Resolve final path by handle");
        if (length >= (uint)sb.Capacity)
        {
            if (length > 32768) throw new Exception("Final handle path exceeded bounded length");
            sb = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, 0);
            if (length == 0 || length >= (uint)sb.Capacity) Check(false, "Read final path by handle");
        }
        string raw = sb.ToString(0, checked((int)length));
        if (raw.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) throw new Exception("Handle resolved to UNC path");
        if (raw.StartsWith("\\\\?\\", StringComparison.Ordinal)) raw = raw.Substring(4);
        return CanonicalLocalPath(raw, "Final handle path");
    }

    static byte[] ReadHandleAllBytes(IntPtr handle, int maxBytes, string description)
    {
        long position;
        Check(SetFilePointerEx(handle, 0, out position, 0), "Rewind " + description);
        using (var ms = new MemoryStream())
        {
            var buffer = new byte[16384];
            for (;;)
            {
                uint bytesRead;
                Check(ReadFile(handle, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero), "Read " + description);
                if (bytesRead == 0) break;
                if (ms.Length + bytesRead > maxBytes) throw new Exception(description + " exceeded maximum size");
                ms.Write(buffer, 0, checked((int)bytesRead));
            }
            return ms.ToArray();
        }
    }

    static string HashHandleContents(IntPtr handle, long expectedBytes)
    {
        if (expectedBytes < 0 || expectedBytes > MaxMcpConfigBytes) throw new Exception("Invalid managed MCP config expected size");
        long position;
        Check(SetFilePointerEx(handle, 0, out position, 0), "Rewind managed MCP config handle");
        var buffer = new byte[16384];
        long total = 0;
        using (SHA256 sha = SHA256.Create())
        {
            for (;;)
            {
                uint bytesRead;
                Check(ReadFile(handle, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero), "Read managed MCP config handle");
                if (bytesRead == 0) break;
                total += bytesRead;
                if (total > expectedBytes) throw new Exception("Managed MCP config byte size exceeded witness");
                sha.TransformBlock(buffer, 0, checked((int)bytesRead), null, 0);
            }
            if (total != expectedBytes) throw new Exception("Managed MCP config byte size mismatch");
            sha.TransformFinalBlock(new byte[0], 0, 0);
            byte[] hash = sha.Hash;
            var sb = new StringBuilder(hash.Length * 2);
            for (int index = 0; index < hash.Length; index++) sb.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
    }

    static void RenameHandleNoReplace(IntPtr handle, string destinationPath)
    {
        string fullDest = CanonicalLocalPath(destinationPath, "Custody rename destination");
        string targetName = fullDest.Length >= 248 ? "\\\\?\\" + fullDest : fullDest;
        byte[] nameBytes = Encoding.Unicode.GetBytes(targetName);
        int rootOffset = IntPtr.Size;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        int totalSize = nameOffset + nameBytes.Length + 2;
        IntPtr buffer = Marshal.AllocHGlobal(totalSize);
        try
        {
            for (int index = 0; index < totalSize; index++) Marshal.WriteByte(buffer, index, 0);
            Marshal.WriteByte(buffer, 0, 0); // ReplaceIfExists = FALSE
            Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero); // RootDirectory = NULL
            Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);
            Check(SetFileInformationByHandle(handle, 3, buffer, checked((uint)totalSize)), "Rename managed MCP config by handle without replace");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    static byte[] ReadKernelDaclBytes(IntPtr handle)
    {
        uint needed;
        GetKernelObjectSecurity(handle, 4, null, 0, out needed);
        int err = Marshal.GetLastWin32Error();
        if (err != 0 && err != 122) Check(false, "Measure kernel object DACL");
        if (needed < 20 || needed > 65536) throw new Exception("Invalid kernel object DACL size: " + needed);
        byte[] buffer = new byte[needed];
        Check(GetKernelObjectSecurity(handle, 4, buffer, needed, out needed), "Read kernel object DACL");
        return buffer;
    }

    static byte[] SerializeDaclBytes(RawSecurityDescriptor descriptor)
    {
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    static void WriteKernelDaclExact(IntPtr handle, RawSecurityDescriptor target)
    {
        byte[] targetBytes = SerializeDaclBytes(target);
        var toWrite = new RawSecurityDescriptor(targetBytes, 0);
        ControlFlags storedFlags = target.ControlFlags;
        // AR preserves AI in this non-propagating write; Windows consumes AR.
        if ((storedFlags & ControlFlags.DiscretionaryAclAutoInherited) != 0)
        {
            toWrite.SetFlags(storedFlags | ControlFlags.DiscretionaryAclAutoInheritRequired);
        }
        WriteKernelDacl(handle, toWrite);
        RawSecurityDescriptor observed = ReadKernelDacl(handle);
        if (!SameDacl(target, observed))
        {
            throw new Exception("Managed MCP config DACL update was not preserved exactly");
        }
    }

    static void ValidateRepresentableDacl(RawSecurityDescriptor descriptor, string label)
    {
        if (descriptor == null || descriptor.DiscretionaryAcl == null || (descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
        {
            throw new Exception("Managed MCP config " + label + " DACL is missing or null");
        }
        if (descriptor.Owner != null || descriptor.Group != null || descriptor.SystemAcl != null)
        {
            throw new Exception("Managed MCP config " + label + " security descriptor contains unexpected sections");
        }
        AceFlags validFlags = AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.NoPropagateInherit | AceFlags.InheritOnly | AceFlags.Inherited;
        RawAcl acl = descriptor.DiscretionaryAcl;
        for (int index = 0; index < acl.Count; index++)
        {
            CommonAce ace = acl[index] as CommonAce;
            if (ace == null)
            {
                throw new Exception("Unrepresentable ACE type in managed MCP config " + label + " DACL");
            }
            if (ace.IsCallback)
            {
                throw new Exception("Unrepresentable callback ACE in managed MCP config " + label + " DACL");
            }
            if (ace.AceQualifier != AceQualifier.AccessAllowed && ace.AceQualifier != AceQualifier.AccessDenied)
            {
                throw new Exception("Unsupported ACE qualifier in managed MCP config " + label + " DACL");
            }
            if (ace.OpaqueLength != 0)
            {
                throw new Exception("Unrepresentable opaque ACE payload in managed MCP config " + label + " DACL");
            }
            if ((ace.AceFlags & ~validFlags) != 0)
            {
                throw new Exception("Unrepresentable ACE flags in managed MCP config " + label + " DACL");
            }
        }
        var roundTripped = new RawSecurityDescriptor(SerializeDaclBytes(descriptor), 0);
        if (!SameDacl(descriptor, roundTripped))
        {
            throw new Exception("Managed MCP config " + label + " DACL failed exact binary round-trip verification");
        }
    }

    static RawSecurityDescriptor ParseValidatedLeaseDacl(string base64, string expectedSha256, string label)
    {
        if (String.IsNullOrEmpty(base64) || base64.Length > 131072 || !IsLowerHex(expectedSha256, 64))
        {
            throw new Exception("Managed MCP config lease " + label + " DACL metadata is missing or invalid");
        }
        byte[] bytes;
        try { bytes = Convert.FromBase64String(base64); }
        catch { throw new Exception("Managed MCP config lease " + label + " DACL encoding is invalid"); }
        if (bytes.Length < 20 || bytes.Length > 65536)
        {
            throw new Exception("Managed MCP config lease " + label + " DACL length is invalid");
        }
        if (!String.Equals(ComputeSha256Hex(bytes), expectedSha256, StringComparison.Ordinal))
        {
            throw new Exception("Managed MCP config lease " + label + " DACL digest mismatch");
        }
        var descriptor = new RawSecurityDescriptor(bytes, 0);
        ValidateRepresentableDacl(descriptor, label);
        return descriptor;
    }

    static uint ExpandFileAccessMask(int mask)
    {
        uint value = unchecked((uint)mask);
        if ((value & 0x10000000u) != 0) value |= 0x001F01FFu;
        if ((value & 0x80000000u) != 0) value |= 0x00120089u;
        if ((value & 0x40000000u) != 0) value |= 0x00120116u;
        if ((value & 0x20000000u) != 0) value |= 0x001200A0u;
        return value;
    }

    static bool IsAllowedCustodySid(SecurityIdentifier sid, SecurityIdentifier controllerUser)
    {
        return controllerUser.Equals(sid) ||
            String.Equals(sid.Value, "S-1-5-18", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(sid.Value, "S-1-5-32-544", StringComparison.OrdinalIgnoreCase);
    }

    static bool CurrentControllerIsAdministrator()
    {
        using (WindowsIdentity current = WindowsIdentity.GetCurrent())
        {
            return new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    static bool DenySidCouldMatchController(SecurityIdentifier sid, SecurityIdentifier controllerUser, bool isAdmin)
    {
        if (controllerUser.Equals(sid) || WorldSid.Equals(sid)) return true;
        if (String.Equals(sid.Value, "S-1-5-11", StringComparison.OrdinalIgnoreCase)) return true;
        if (String.Equals(sid.Value, "S-1-5-32-545", StringComparison.OrdinalIgnoreCase)) return true;
        if (isAdmin && String.Equals(sid.Value, "S-1-5-32-544", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    static void ValidateMonotonicCustodyDacl(RawSecurityDescriptor original, RawSecurityDescriptor custody, SecurityIdentifier controllerUser)
    {
        ValidateRepresentableDacl(original, "original");
        ValidateRepresentableDacl(custody, "custody");
        if ((custody.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
            (custody.ControlFlags & (ControlFlags.DiscretionaryAclAutoInherited | ControlFlags.DiscretionaryAclAutoInheritRequired)) != 0)
        {
            throw new Exception("Tightened custody DACL is not strictly protected against inheritance");
        }
        var originalDenies = new List<CommonAce>();
        var originalAllows = new List<CommonAce>();
        for (int index = 0; index < original.DiscretionaryAcl.Count; index++)
        {
            CommonAce ace = (CommonAce)original.DiscretionaryAcl[index];
            if (ace.AceQualifier == AceQualifier.AccessDenied) originalDenies.Add(ace);
            else originalAllows.Add(ace);
        }
        var custodyDenies = new List<CommonAce>();
        bool isAdmin = CurrentControllerIsAdministrator();
        uint deniedForController = 0;
        uint allowedForController = 0;
        for (int index = 0; index < custody.DiscretionaryAcl.Count; index++)
        {
            CommonAce ace = (CommonAce)custody.DiscretionaryAcl[index];
            if ((ace.AceFlags & AceFlags.Inherited) != 0)
            {
                throw new Exception("Tightened custody DACL cannot retain inherited ACE flags");
            }
            if (ace.AceQualifier == AceQualifier.AccessDenied)
            {
                custodyDenies.Add(ace);
                if ((ace.AceFlags & AceFlags.InheritOnly) == 0 && DenySidCouldMatchController(ace.SecurityIdentifier, controllerUser, isAdmin))
                {
                    deniedForController |= ExpandFileAccessMask(ace.AccessMask);
                }
                continue;
            }
            if (ace.SecurityIdentifier.Value.StartsWith("S-1-15-", StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Tightened custody DACL still permits an AppContainer or capability SID");
            }
            if (!IsAllowedCustodySid(ace.SecurityIdentifier, controllerUser))
            {
                throw new Exception("Tightened custody DACL permits an unauthorized principal");
            }
            bool matchedOriginal = false;
            for (int origIndex = 0; origIndex < originalAllows.Count; origIndex++)
            {
                CommonAce origAce = originalAllows[origIndex];
                if (origAce.SecurityIdentifier.Equals(ace.SecurityIdentifier) &&
                    origAce.AccessMask == ace.AccessMask &&
                    (origAce.AceFlags & ~AceFlags.Inherited) == ace.AceFlags)
                {
                    matchedOriginal = true;
                    break;
                }
            }
            if (!matchedOriginal)
            {
                throw new Exception("Tightened custody DACL widened or added an allow ACE beyond the original DACL");
            }
            if ((ace.AceFlags & AceFlags.InheritOnly) == 0 &&
                (controllerUser.Equals(ace.SecurityIdentifier) ||
                 (isAdmin && String.Equals(ace.SecurityIdentifier.Value, "S-1-5-32-544", StringComparison.OrdinalIgnoreCase))))
            {
                allowedForController |= (ExpandFileAccessMask(ace.AccessMask) & ~deniedForController);
            }
        }
        if (custodyDenies.Count != originalDenies.Count)
        {
            throw new Exception("Tightened custody DACL did not preserve all original deny ACEs");
        }
        for (int index = 0; index < originalDenies.Count; index++)
        {
            CommonAce expectedDeny = originalDenies[index];
            CommonAce actualDeny = custodyDenies[index];
            if (!expectedDeny.SecurityIdentifier.Equals(actualDeny.SecurityIdentifier) ||
                expectedDeny.AccessMask != actualDeny.AccessMask ||
                (expectedDeny.AceFlags & ~AceFlags.Inherited) != actualDeny.AceFlags)
            {
                throw new Exception("Tightened custody DACL altered an original deny ACE");
            }
        }
        if ((allowedForController & RequiredCustodyFileAccess) != RequiredCustodyFileAccess)
        {
            throw new Exception("Original managed MCP config DACL does not grant controller recovery rights without widening; failing closed");
        }
    }

    static RawSecurityDescriptor BuildMonotonicCustodyDacl(RawSecurityDescriptor original, SecurityIdentifier controllerUser)
    {
        ValidateRepresentableDacl(original, "original");
        var tightenedAcl = new RawAcl(original.DiscretionaryAcl.Revision, original.DiscretionaryAcl.Count);
        int insertIndex = 0;
        for (int index = 0; index < original.DiscretionaryAcl.Count; index++)
        {
            CommonAce ace = (CommonAce)original.DiscretionaryAcl[index];
            AceFlags keptFlags = ace.AceFlags & ~AceFlags.Inherited;
            if (ace.AceQualifier == AceQualifier.AccessDenied)
            {
                tightenedAcl.InsertAce(insertIndex++, new CommonAce(keptFlags, AceQualifier.AccessDenied, ace.AccessMask, ace.SecurityIdentifier, false, null));
                continue;
            }
            if (ace.SecurityIdentifier.Value.StartsWith("S-1-15-", StringComparison.OrdinalIgnoreCase)) continue;
            if (!IsAllowedCustodySid(ace.SecurityIdentifier, controllerUser)) continue;
            tightenedAcl.InsertAce(insertIndex++, new CommonAce(keptFlags, AceQualifier.AccessAllowed, ace.AccessMask, ace.SecurityIdentifier, false, null));
        }
        var built = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected,
            null,
            null,
            null,
            tightenedAcl);
        var normalized = new RawSecurityDescriptor(SerializeDaclBytes(built), 0);
        ValidateMonotonicCustodyDacl(original, normalized, controllerUser);
        return normalized;
    }

    static RawSecurityDescriptor BuildProtectedControllerDacl(SecurityIdentifier controllerUser, bool isDirectory, bool includeOwner)
    {
        AceFlags flags = isDirectory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None;
        int mask = (int)FileSystemRights.FullControl;
        var acl = new RawAcl(RawAcl.AclRevision, 2);
        acl.InsertAce(0, new CommonAce(flags, AceQualifier.AccessAllowed, mask, controllerUser, false, null));
        acl.InsertAce(1, new CommonAce(flags, AceQualifier.AccessAllowed, mask, new SecurityIdentifier("S-1-5-18"), false, null));
        return new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected,
            includeOwner ? controllerUser : null,
            null,
            null,
            acl);
    }

    static bool IsProtectedControllerDacl(RawSecurityDescriptor descriptor, SecurityIdentifier controllerUser, bool isDirectory)
    {
        if (descriptor == null || descriptor.DiscretionaryAcl == null) return false;
        if ((descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0) return false;
        AceFlags expectedFlags = isDirectory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None;
        int expectedMask = (int)FileSystemRights.FullControl;
        var systemSid = new SecurityIdentifier("S-1-5-18");
        RawAcl acl = descriptor.DiscretionaryAcl;
        if (acl.Count != 2) return false;
        bool sawUser = false, sawSystem = false;
        for (int index = 0; index < acl.Count; index++)
        {
            CommonAce ace = acl[index] as CommonAce;
            if (ace == null || ace.IsCallback || ace.AceQualifier != AceQualifier.AccessAllowed ||
                ace.AceFlags != expectedFlags || ace.AccessMask != expectedMask) return false;
            if (ace.SecurityIdentifier.Value.StartsWith("S-1-15-", StringComparison.OrdinalIgnoreCase)) return false;
            if (controllerUser.Equals(ace.SecurityIdentifier)) sawUser = true;
            else if (systemSid.Equals(ace.SecurityIdentifier)) sawSystem = true;
            else return false;
        }
        return sawUser && sawSystem;
    }

    static void EnforceProtectedControllerDaclByHandle(IntPtr handle, SecurityIdentifier controllerUser, bool isDirectory)
    {
        RawSecurityDescriptor desired = BuildProtectedControllerDacl(controllerUser, isDirectory, false);
        WriteKernelDacl(handle, desired);
        RawSecurityDescriptor verified = ReadKernelDacl(handle);
        if (!IsProtectedControllerDacl(verified, controllerUser, isDirectory))
        {
            throw new Exception("Protected controller DACL verification failed");
        }
    }

    static bool CreateDirectoryWithProtectedDacl(string directoryPath, SecurityIdentifier controllerUser, bool allowExisting)
    {
        RawSecurityDescriptor descriptor = BuildProtectedControllerDacl(controllerUser, true, true);
        byte[] sdBytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(sdBytes, 0);
        IntPtr pSd = Marshal.AllocHGlobal(sdBytes.Length);
        IntPtr pSa = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityAttributes)));
        try
        {
            Marshal.Copy(sdBytes, 0, pSd, sdBytes.Length);
            Marshal.StructureToPtr(new SecurityAttributes { length = Marshal.SizeOf(typeof(SecurityAttributes)), descriptor = pSd, inherit = 0 }, pSa, false);
            if (CreateDirectory(directoryPath, pSa)) return true;
            int error = Marshal.GetLastWin32Error();
            if (allowExisting && error == 183) return false;
            throw new Win32Exception(error, "Create protected custody directory (Win32 " + error + ")");
        }
        finally
        {
            Marshal.FreeHGlobal(pSa);
            Marshal.FreeHGlobal(pSd);
        }
    }

    static void ValidateMcpCustodyRequest(McpCustodyRequest custody)
    {
        if (custody == null) return;
        Guid executionGuid;
        if (String.IsNullOrEmpty(custody.executionId) || !Guid.TryParseExact(custody.executionId, "D", out executionGuid) ||
            !IsLowerHex(custody.sha256, 64) || custody.bytes < 0 || custody.bytes > MaxMcpConfigBytes)
        {
            throw new Exception("Invalid managed MCP config custody request");
        }
    }

    static void ValidateMcpCustodyLease(McpCustodyLease custody, string expectedCwd, string canonicalState, Guid leaseNonce)
    {
        if (custody == null) return;
        Guid executionGuid;
        if (custody.version != 1 || String.IsNullOrEmpty(custody.executionId) || !Guid.TryParseExact(custody.executionId, "D", out executionGuid) ||
            !IsLowerHex(custody.sha256, 64) || custody.bytes < 0 || custody.bytes > MaxMcpConfigBytes)
        {
            throw new Exception("Invalid managed MCP config custody lease");
        }
        string fullCwd = CanonicalLocalPath(expectedCwd, "Custody workspace copy");
        string expectedAgents = Path.Combine(fullCwd, ".agents");
        string expectedSource = Path.Combine(expectedAgents, "mcp_config.json");
        string expectedCustodyDir = Path.Combine(Path.Combine(canonicalState, "windows-lpac-custody"), leaseNonce.ToString("N"));
        string expectedCustodyPath = Path.Combine(expectedCustodyDir, "mcp_config.json");
        if (String.IsNullOrEmpty(custody.agentsPath) || String.IsNullOrEmpty(custody.sourcePath) ||
            String.IsNullOrEmpty(custody.custodyDirectory) || String.IsNullOrEmpty(custody.custodyPath) ||
            !String.Equals(CanonicalLocalPath(custody.agentsPath, "Custody agents path"), expectedAgents, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(CanonicalLocalPath(custody.sourcePath, "Custody source path"), expectedSource, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(CanonicalLocalPath(custody.custodyDirectory, "Custody slot directory"), expectedCustodyDir, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(CanonicalLocalPath(custody.custodyPath, "Custody file path"), expectedCustodyPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new Exception("Managed MCP config custody lease path mismatch");
        }
        ParseValidatedLeaseDacl(custody.originalDaclBase64, custody.originalDaclSha256, "original");
        ParseValidatedLeaseDacl(custody.custodyDaclBase64, custody.custodyDaclSha256, "custody");
    }

    static McpStagingWitness ReadValidatedMcpWitness(McpCustodyRequest request, string cwd, string canonicalState, JavaScriptSerializer serializer)
    {
        ValidateMcpCustodyRequest(request);
        Guid executionGuid = Guid.ParseExact(request.executionId, "D");
        string witnessDir = Path.Combine(canonicalState, "execution-mcp-witnesses");
        string witnessPath = Path.Combine(witnessDir, executionGuid.ToString("D").ToLowerInvariant() + ".json");
        using (var dirPin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = 1 })
        {
            ValidatePathComponents(witnessDir, dirPin, false, 1);
            if (!dirPin.grant.directory) throw new Exception("Managed MCP config staging witness directory is invalid");
            IntPtr witnessHandle = CreateFile(witnessPath, FileReadData | FileReadAttributes | StandardRightsRead | Synchronize, FileShareRead, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
            if (witnessHandle == InvalidHandle) Check(false, "Open managed MCP config staging witness by handle");
            try
            {
                ByHandleFileInformation witnessInfo;
                Check(GetFileInformationByHandle(witnessHandle, out witnessInfo), "Inspect managed MCP config staging witness handle");
                if ((witnessInfo.attributes & (uint)FileAttributes.Directory) != 0 || (witnessInfo.attributes & (uint)FileAttributes.ReparsePoint) != 0)
                {
                    throw new Exception("Managed MCP config staging witness is a directory or reparse point");
                }
                if (witnessInfo.links != 1) throw new Exception("Managed MCP config staging witness has multiple hard links");
                ulong witnessSize = ((ulong)witnessInfo.sizeHigh << 32) | witnessInfo.sizeLow;
                if (witnessSize == 0 || witnessSize > 65536) throw new Exception("Managed MCP config staging witness size is invalid");
                if (!String.Equals(FinalPathByHandle(witnessHandle), witnessPath, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception("Managed MCP config staging witness handle path mismatch");
                }
                byte[] witnessBytes = ReadHandleAllBytes(witnessHandle, 65536, "managed MCP config staging witness");
                if ((ulong)witnessBytes.Length != witnessSize) throw new Exception("Managed MCP config staging witness byte length mismatch");
                McpStagingWitness witness = serializer.Deserialize<McpStagingWitness>(Encoding.UTF8.GetString(witnessBytes));
                if (witness == null || witness.version != 1) throw new Exception("Managed MCP config staging witness is invalid");
                Guid witnessGuid;
                if (String.IsNullOrEmpty(witness.executionId) || !Guid.TryParseExact(witness.executionId, "D", out witnessGuid) || !witnessGuid.Equals(executionGuid))
                {
                    throw new Exception("Managed MCP config staging witness executionId mismatch");
                }
                string fullCwd = CanonicalLocalPath(cwd, "Workspace copy");
                string expectedAgents = Path.Combine(fullCwd, ".agents");
                string expectedSource = Path.Combine(expectedAgents, "mcp_config.json");
                if (String.IsNullOrEmpty(witness.copyDirectory) || String.IsNullOrEmpty(witness.agentsDirectory) || String.IsNullOrEmpty(witness.mcpConfigPath) ||
                    !String.Equals(CanonicalLocalPath(witness.copyDirectory, "Witness copyDirectory"), fullCwd, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(CanonicalLocalPath(witness.agentsDirectory, "Witness agentsDirectory"), expectedAgents, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(CanonicalLocalPath(witness.mcpConfigPath, "Witness mcpConfigPath"), expectedSource, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception("Managed MCP config staging witness path mismatch");
                }
                if (!IsValidUint32(witness.copyVolume) || !IsValidUint32(witness.copyFileIndexHigh) || !IsValidUint32(witness.copyFileIndexLow) ||
                    !IsValidUint32(witness.agentsVolume) || !IsValidUint32(witness.agentsFileIndexHigh) || !IsValidUint32(witness.agentsFileIndexLow) ||
                    !IsValidUint32(witness.volume) || !IsValidUint32(witness.fileIndexHigh) || !IsValidUint32(witness.fileIndexLow))
                {
                    throw new Exception("Managed MCP config staging witness object identity is incomplete");
                }
                if (!witness.bytes.HasValue || witness.bytes.Value != request.bytes || !IsLowerHex(witness.sha256, 64) ||
                    !String.Equals(witness.sha256, request.sha256, StringComparison.Ordinal))
                {
                    throw new Exception("Managed MCP config staging witness digest or size mismatch");
                }
                return witness;
            }
            finally { CloseHandle(witnessHandle); }
        }
    }

    static void PinAndVerifyDirectoryNoReparse(string directoryPath, uint expectedVolume, uint expectedIndexHigh, uint expectedIndexLow, string description, out PinnedTarget pin)
    {
        pin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = 1 };
        try
        {
            ValidatePathComponents(directoryPath, pin, false, 1);
            if (!pin.grant.directory || (GetFileAttributes(pin.grant.path) & (uint)FileAttributes.ReparsePoint) != 0 ||
                pin.grant.volume != expectedVolume || pin.grant.fileIndexHigh != expectedIndexHigh || pin.grant.fileIndexLow != expectedIndexLow)
            {
                throw new Exception(description + " identity or type does not match staging witness");
            }
        }
        catch { pin.Dispose(); pin = null; throw; }
    }

    static IntPtr OpenCustodyPinnedDirectoryHandle(string directoryPath, uint expectedVolume, uint expectedIndexHigh, uint expectedIndexLow, string description)
    {
        IntPtr handle = CreateFile(directoryPath, FileListDirectory, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == InvalidHandle) Check(false, "Pin " + description + " directory handle");
        try
        {
            ByHandleFileInformation info;
            Check(GetFileInformationByHandle(handle, out info), "Inspect " + description + " directory handle");
            if ((info.attributes & (uint)FileAttributes.Directory) == 0 || (info.attributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                throw new Exception(description + " handle is not a non-reparse directory");
            }
            if (info.volume != expectedVolume || info.indexHigh != expectedIndexHigh || info.indexLow != expectedIndexLow)
            {
                throw new Exception(description + " handle identity does not match staging witness");
            }
            if (!String.Equals(FinalPathByHandle(handle), directoryPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception(description + " handle canonical path mismatch");
            }
            return handle;
        }
        catch
        {
            CloseHandle(handle);
            throw;
        }
    }

    static string EnsureProtectedStateSubdirectory(string canonicalState, string directoryName, SecurityIdentifier controllerUser, string description)
    {
        using (var statePin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = 1 })
        {
            ValidatePathComponents(canonicalState, statePin, false, 1);
            if (!statePin.grant.directory) throw new Exception("State directory is not a directory");
            string protectedDir = Path.Combine(canonicalState, directoryName);
            CreateDirectoryWithProtectedDacl(protectedDir, controllerUser, true);
            using (var dirPin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = 1 })
            {
                ValidatePathComponents(protectedDir, dirPin, false, 1);
                if (!dirPin.grant.directory || (GetFileAttributes(protectedDir) & (uint)FileAttributes.ReparsePoint) != 0)
                {
                    throw new Exception(description + " is unavailable or linked");
                }
            }
            IntPtr dirHandle = CreateFile(protectedDir, StandardRightsRead | StandardRightsWriteDac, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (dirHandle == InvalidHandle) Check(false, "Open " + description);
            try
            {
                ByHandleFileInformation info;
                Check(GetFileInformationByHandle(dirHandle, out info), "Inspect " + description);
                if ((info.attributes & (uint)FileAttributes.Directory) == 0 || (info.attributes & (uint)FileAttributes.ReparsePoint) != 0)
                {
                    throw new Exception(description + " is invalid or linked");
                }
                if (!String.Equals(FinalPathByHandle(dirHandle), protectedDir, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception(description + " canonical path mismatch");
                }
                RawSecurityDescriptor current = ReadKernelDacl(dirHandle);
                if (!IsProtectedControllerDacl(current, controllerUser, true))
                {
                    EnforceProtectedControllerDaclByHandle(dirHandle, controllerUser, true);
                }
            }
            finally { CloseHandle(dirHandle); }
            return protectedDir;
        }
    }

    static string EnsureProtectedCustodyRoot(string canonicalState, SecurityIdentifier controllerUser)
    {
        return EnsureProtectedStateSubdirectory(canonicalState, "windows-lpac-custody", controllerUser, "Protected custody root");
    }

    static string EnsureProtectedQuarantineRoot(string canonicalState, SecurityIdentifier controllerUser)
    {
        return EnsureProtectedStateSubdirectory(canonicalState, "windows-lpac-custody-quarantine", controllerUser, "Protected custody quarantine root");
    }

    static McpCustodyHold AcquireMcpConfigCustody(
        McpCustodyRequest request,
        string cwd,
        string canonicalState,
        Guid leaseNonce,
        ControllerIdentity controller,
        Lease lease,
        string leaseFile,
        ref bool leaseWritten,
        JavaScriptSerializer serializer)
    {
        McpStagingWitness witness = ReadValidatedMcpWitness(request, cwd, canonicalState, serializer);
        string fullCwd = CanonicalLocalPath(cwd, "Workspace copy");
        string agentsPath = Path.Combine(fullCwd, ".agents");
        string sourcePath = Path.Combine(agentsPath, "mcp_config.json");
        PinnedTarget copyPin = null, agentsPin = null;
        IntPtr fileHandle = IntPtr.Zero, slotDirHandle = IntPtr.Zero, copyDirHandle = IntPtr.Zero, agentsDirHandle = IntPtr.Zero;
        string slotDir = null;
        bool slotCreated = false;
        try
        {
            PinAndVerifyDirectoryNoReparse(fullCwd, (uint)witness.copyVolume.Value, (uint)witness.copyFileIndexHigh.Value, (uint)witness.copyFileIndexLow.Value, "Workspace copy parent", out copyPin);
            copyDirHandle = OpenCustodyPinnedDirectoryHandle(fullCwd, (uint)witness.copyVolume.Value, (uint)witness.copyFileIndexHigh.Value, (uint)witness.copyFileIndexLow.Value, "Workspace copy parent");
            PinAndVerifyDirectoryNoReparse(agentsPath, (uint)witness.agentsVolume.Value, (uint)witness.agentsFileIndexHigh.Value, (uint)witness.agentsFileIndexLow.Value, "Managed .agents parent", out agentsPin);
            agentsDirHandle = OpenCustodyPinnedDirectoryHandle(agentsPath, (uint)witness.agentsVolume.Value, (uint)witness.agentsFileIndexHigh.Value, (uint)witness.agentsFileIndexLow.Value, "Managed .agents parent");

            fileHandle = CreateFile(sourcePath, RequiredCustodyFileAccess, 0, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
            if (fileHandle == InvalidHandle) Check(false, "Open managed MCP config exclusively by handle");

            ByHandleFileInformation info;
            Check(GetFileInformationByHandle(fileHandle, out info), "Inspect managed MCP config handle");
            if ((info.attributes & (uint)FileAttributes.Directory) != 0 || (info.attributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                throw new Exception("Managed MCP config is a directory or reparse point");
            }
            if (info.links != 1) throw new Exception("Managed MCP config has multiple hard links");
            if (info.volume != (uint)witness.volume.Value || info.indexHigh != (uint)witness.fileIndexHigh.Value || info.indexLow != (uint)witness.fileIndexLow.Value)
            {
                throw new Exception("Managed MCP config object identity does not match staging witness");
            }
            ulong actualSize = ((ulong)info.sizeHigh << 32) | info.sizeLow;
            if (actualSize != (ulong)witness.bytes.Value) throw new Exception("Managed MCP config size does not match staging witness");
            if (!String.Equals(FinalPathByHandle(fileHandle), sourcePath, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Managed MCP config handle path does not match pinned .agents path");
            }
            string actualSha256 = HashHandleContents(fileHandle, witness.bytes.Value);
            if (!String.Equals(actualSha256, witness.sha256, StringComparison.Ordinal))
            {
                throw new Exception("Managed MCP config content hash does not match staging witness");
            }
            ByHandleFileInformation recheck;
            Check(GetFileInformationByHandle(fileHandle, out recheck), "Re-verify managed MCP config handle");
            if (recheck.links != 1 || recheck.volume != info.volume || recheck.indexHigh != info.indexHigh || recheck.indexLow != info.indexLow ||
                (((ulong)recheck.sizeHigh << 32) | recheck.sizeLow) != actualSize)
            {
                throw new Exception("Managed MCP config changed during verification");
            }

            // Capture complete original DACL (including flags) by handle and validate monotonic tightening BEFORE any mutation.
            byte[] originalDaclBytes = ReadKernelDaclBytes(fileHandle);
            var originalDacl = new RawSecurityDescriptor(originalDaclBytes, 0);
            ValidateRepresentableDacl(originalDacl, "original");
            byte[] canonicalOriginalBytes = SerializeDaclBytes(originalDacl);
            RawSecurityDescriptor tightenedDacl = BuildMonotonicCustodyDacl(originalDacl, controller.user);
            byte[] canonicalTightenedBytes = SerializeDaclBytes(tightenedDacl);

            string custodyRoot = EnsureProtectedCustodyRoot(canonicalState, controller.user);
            slotDir = Path.Combine(custodyRoot, leaseNonce.ToString("N"));
            CreateDirectoryWithProtectedDacl(slotDir, controller.user, false);
            slotCreated = true;

            slotDirHandle = CreateFile(slotDir, StandardRightsRead | StandardRightsWriteDac, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (slotDirHandle == InvalidHandle) Check(false, "Pin exclusive custody slot directory");
            ByHandleFileInformation slotInfo;
            Check(GetFileInformationByHandle(slotDirHandle, out slotInfo), "Inspect exclusive custody slot directory");
            if ((slotInfo.attributes & (uint)FileAttributes.Directory) == 0 || (slotInfo.attributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                throw new Exception("Exclusive custody slot directory is invalid or linked");
            }
            if (!String.Equals(FinalPathByHandle(slotDirHandle), slotDir, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Exclusive custody slot directory canonical path mismatch");
            }
            if (!IsProtectedControllerDacl(ReadKernelDacl(slotDirHandle), controller.user, true))
            {
                EnforceProtectedControllerDaclByHandle(slotDirHandle, controller.user, true);
            }
            if (info.volume != slotInfo.volume)
            {
                throw new Exception("Managed MCP config and protected custody directory are on different volumes");
            }

            string custodyPath = Path.Combine(slotDir, "mcp_config.json");
            if (GetFileAttributes(custodyPath) != InvalidFileAttributes || Marshal.GetLastWin32Error() != 2)
            {
                throw new Exception("Exclusive custody destination already exists or is inaccessible");
            }

            var custodyLease = new McpCustodyLease
            {
                version = 1,
                executionId = witness.executionId.ToLowerInvariant(),
                sourcePath = sourcePath,
                agentsPath = agentsPath,
                custodyDirectory = slotDir,
                custodyPath = custodyPath,
                copyVolume = (uint)witness.copyVolume.Value,
                copyFileIndexHigh = (uint)witness.copyFileIndexHigh.Value,
                copyFileIndexLow = (uint)witness.copyFileIndexLow.Value,
                agentsVolume = (uint)witness.agentsVolume.Value,
                agentsFileIndexHigh = (uint)witness.agentsFileIndexHigh.Value,
                agentsFileIndexLow = (uint)witness.agentsFileIndexLow.Value,
                custodyDirVolume = slotInfo.volume,
                custodyDirFileIndexHigh = slotInfo.indexHigh,
                custodyDirFileIndexLow = slotInfo.indexLow,
                volume = info.volume,
                fileIndexHigh = info.indexHigh,
                fileIndexLow = info.indexLow,
                bytes = witness.bytes.Value,
                sha256 = witness.sha256,
                originalDaclBase64 = Convert.ToBase64String(canonicalOriginalBytes),
                originalDaclSha256 = ComputeSha256Hex(canonicalOriginalBytes),
                custodyDaclBase64 = Convert.ToBase64String(canonicalTightenedBytes),
                custodyDaclSha256 = ComputeSha256Hex(canonicalTightenedBytes),
            };

            lease.mcpCustody = custodyLease;
            WriteLease(leaseFile, lease, !leaseWritten, serializer);
            leaseWritten = true;

            // Rename without replace FIRST (into protected custody slot), then monotonically tighten DACL by handle.
            RenameHandleNoReplace(fileHandle, custodyPath);
            if (!String.Equals(FinalPathByHandle(fileHandle), custodyPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Managed MCP config did not land at pinned custody destination");
            }
            if (GetFileAttributes(sourcePath) != InvalidFileAttributes || Marshal.GetLastWin32Error() != 2)
            {
                throw new Exception("Managed MCP config still appears at source path after custody move");
            }

            if (!SameDacl(tightenedDacl, ReadKernelDacl(fileHandle)))
            {
                WriteKernelDaclExact(fileHandle, tightenedDacl);
            }
            ValidateMonotonicCustodyDacl(originalDacl, ReadKernelDacl(fileHandle), controller.user);

            var hold = new McpCustodyHold
            {
                lease = custodyLease,
                fileHandle = fileHandle,
                slotDirHandle = slotDirHandle,
                copyDirHandle = copyDirHandle,
                agentsDirHandle = agentsDirHandle,
                copyPin = copyPin,
                agentsPin = agentsPin,
            };
            fileHandle = IntPtr.Zero;
            slotDirHandle = IntPtr.Zero;
            copyDirHandle = IntPtr.Zero;
            agentsDirHandle = IntPtr.Zero;
            copyPin = null;
            agentsPin = null;
            slotCreated = false;
            return hold;
        }
        catch
        {
            if (!leaseWritten && lease != null) lease.mcpCustody = null;
            if (fileHandle != IntPtr.Zero && fileHandle != InvalidHandle) CloseHandle(fileHandle);
            if (slotDirHandle != IntPtr.Zero && slotDirHandle != InvalidHandle) CloseHandle(slotDirHandle);
            if (agentsDirHandle != IntPtr.Zero && agentsDirHandle != InvalidHandle) CloseHandle(agentsDirHandle);
            if (copyDirHandle != IntPtr.Zero && copyDirHandle != InvalidHandle) CloseHandle(copyDirHandle);
            if (slotCreated && !leaseWritten && slotDir != null)
            {
                try { Directory.Delete(slotDir, false); } catch { }
            }
            throw;
        }
        finally
        {
            if (agentsPin != null) agentsPin.Dispose();
            if (copyPin != null) copyPin.Dispose();
        }
    }

    static void DeleteVerifiedEmptyCustodySlot(McpCustodyLease custody, IntPtr existingSlotHandle)
    {
        IntPtr slotHandle = existingSlotHandle;
        try
        {
            if (slotHandle == IntPtr.Zero || slotHandle == InvalidHandle)
            {
                uint attrs = GetFileAttributes(custody.custodyDirectory);
                if (attrs == InvalidFileAttributes)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 2 || err == 3) return;
                    throw new Win32Exception(err, "Inspect custody slot directory");
                }
                if ((attrs & (uint)FileAttributes.Directory) == 0 || (attrs & (uint)FileAttributes.ReparsePoint) != 0)
                {
                    throw new Exception("Custody slot directory is invalid or linked");
                }
                slotHandle = CreateFile(custody.custodyDirectory, 0, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
                if (slotHandle == InvalidHandle) Check(false, "Open custody slot directory for cleanup");
            }
            ByHandleFileInformation slotInfo;
            Check(GetFileInformationByHandle(slotHandle, out slotInfo), "Verify custody slot directory identity");
            if ((slotInfo.attributes & (uint)FileAttributes.Directory) == 0 || (slotInfo.attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
                slotInfo.volume != custody.custodyDirVolume || slotInfo.indexHigh != custody.custodyDirFileIndexHigh || slotInfo.indexLow != custody.custodyDirFileIndexLow ||
                !String.Equals(FinalPathByHandle(slotHandle), custody.custodyDirectory, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Custody slot directory identity changed before removal");
            }
            CloseHandle(slotHandle);
            slotHandle = IntPtr.Zero;
            Directory.Delete(custody.custodyDirectory, false);
        }
        finally
        {
            if (slotHandle != IntPtr.Zero && slotHandle != InvalidHandle) CloseHandle(slotHandle);
        }
    }

    static void VerifyHandleMatchesCustody(IntPtr handle, McpCustodyLease custody, string expectedPath)
    {
        ByHandleFileInformation info;
        Check(GetFileInformationByHandle(handle, out info), "Inspect managed MCP config handle");
        if ((info.attributes & (uint)FileAttributes.Directory) != 0 || (info.attributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            throw new Exception("Managed MCP config handle is a directory or reparse point");
        }
        if (info.links != 1) throw new Exception("Managed MCP config handle has multiple hard links");
        if (info.volume != custody.volume || info.indexHigh != custody.fileIndexHigh || info.indexLow != custody.fileIndexLow)
        {
            throw new Exception("Managed MCP config identity changed in custody");
        }
        ulong actualSize = ((ulong)info.sizeHigh << 32) | info.sizeLow;
        if (actualSize != (ulong)custody.bytes) throw new Exception("Managed MCP config size changed in custody");
        if (!String.Equals(FinalPathByHandle(handle), expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new Exception("Managed MCP config handle path mismatch");
        }
        string actualSha = HashHandleContents(handle, custody.bytes);
        if (!String.Equals(actualSha, custody.sha256, StringComparison.Ordinal))
        {
            throw new Exception("Managed MCP config content hash changed in custody");
        }
    }

    enum McpCustodyOutcome
    {
        Restored,
        Quarantined,
    }

    static bool TryInspectDirectoryForRestore(string directoryPath, uint expectedVolume, uint expectedIndexHigh, uint expectedIndexLow, string missingReason, string changedReason, out string conflictReason)
    {
        string canonical = CanonicalLocalPath(directoryPath, "Restore parent directory");
        IntPtr handle = CreateFile(canonical, 0, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == InvalidHandle)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == 2)
            {
                conflictReason = missingReason;
                return false;
            }
            throw new Win32Exception(err, "Inspect restore parent directory (Win32 " + err + ")");
        }
        try
        {
            ByHandleFileInformation info;
            Check(GetFileInformationByHandle(handle, out info), "Read restore parent directory identity");
            if ((info.attributes & (uint)FileAttributes.Directory) == 0 ||
                (info.attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
                info.volume != expectedVolume ||
                info.indexHigh != expectedIndexHigh ||
                info.indexLow != expectedIndexLow ||
                !String.Equals(FinalPathByHandle(handle), canonical, StringComparison.OrdinalIgnoreCase))
            {
                conflictReason = changedReason;
                return false;
            }
            conflictReason = null;
            return true;
        }
        finally { CloseHandle(handle); }
    }

    static bool IsOwnedCopyPositivelyMissing(Lease lease, string canonicalState)
    {
        if (lease == null || String.IsNullOrEmpty(lease.cwd)) return false;
        string fullCopy, rootKey, metadataPath;
        if (!IsEarlierLease(lease) && TryGetCanonicalWorkspaceRootKey(lease.cwd, canonicalState, out fullCopy, out rootKey, out metadataPath))
        {
            try
            {
                using (var statePin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = 1 })
                {
                    ValidatePathComponents(canonicalState, statePin, false, 1);
                    if (!statePin.grant.directory) return false;
                }
            }
            catch { return false; }

            string workspacesDir = Path.Combine(canonicalState, "workspaces");
            uint workspacesAttrs = GetFileAttributes(workspacesDir);
            if (workspacesAttrs == InvalidFileAttributes)
            {
                return Marshal.GetLastWin32Error() == 2;
            }
            if ((workspacesAttrs & (uint)FileAttributes.ReparsePoint) != 0 || (workspacesAttrs & (uint)FileAttributes.Directory) == 0)
            {
                return false;
            }
            string workspaceDir = Path.Combine(workspacesDir, rootKey);
            uint workspaceAttrs = GetFileAttributes(workspaceDir);
            if (workspaceAttrs == InvalidFileAttributes)
            {
                return Marshal.GetLastWin32Error() == 2;
            }
            if ((workspaceAttrs & (uint)FileAttributes.ReparsePoint) != 0 || (workspaceAttrs & (uint)FileAttributes.Directory) == 0)
            {
                return false;
            }
            uint copyAttrs = GetFileAttributes(fullCopy);
            if (copyAttrs == InvalidFileAttributes)
            {
                return Marshal.GetLastWin32Error() == 2;
            }
            return false;
        }
        try
        {
            string ownedTemp = OwnedTemporaryPath(lease.cwd, LeasePrefix(lease, "copy"));
            string tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
            using (var tempPin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = 1 })
            {
                ValidatePathComponents(tempRoot, tempPin, false, 1);
                if (!tempPin.grant.directory) return false;
            }
            uint attrs = GetFileAttributes(ownedTemp);
            if (attrs == InvalidFileAttributes)
            {
                return Marshal.GetLastWin32Error() == 2;
            }
            return false;
        }
        catch { return false; }
    }

    static bool IsWorkspaceMetadataPositivelyMissing(Lease lease, string canonicalState)
    {
        string fullCopy, rootKey, metadataPath;
        if (!TryGetCanonicalWorkspaceRootKey(lease.cwd, canonicalState, out fullCopy, out rootKey, out metadataPath)) return false;
        uint attrs = GetFileAttributes(metadataPath);
        if (attrs != InvalidFileAttributes) return false;
        int err = Marshal.GetLastWin32Error();
        return err == 2 || err == 3;
    }

    static void ValidateCommittedLeaseMetadataFile(Lease lease, string stateDirectory, string canonicalState, JavaScriptSerializer serializer)
    {
        Guid capNonce;
        if (lease == null || String.IsNullOrEmpty(lease.capabilityNonce) || !Guid.TryParseExact(lease.capabilityNonce, "D", out capNonce) ||
            lease.grants == null || lease.grants.Length != 1 || lease.grants[0] == null || !IsLowerHex(lease.nativeDaclSha256, 64))
        {
            throw new Exception("Committed workspace initialization lease is incomplete");
        }
        string fullCopy, rootKey, metadataPath;
        if (!TryGetCanonicalWorkspaceRootKey(lease.cwd, stateDirectory, out fullCopy, out rootKey, out metadataPath))
        {
            throw new Exception("Committed workspace initialization lease target is not canonical");
        }
        if (IsWorkspaceMetadataPositivelyMissing(lease, canonicalState))
        {
            if (IsOwnedCopyPositivelyMissing(lease, canonicalState)) return;
            throw new Exception("Committed workspace metadata is missing while canonical copy still exists");
        }
        uint metaAttrs = GetFileAttributes(metadataPath);
        if (metaAttrs == InvalidFileAttributes || (metaAttrs & (uint)FileAttributes.ReparsePoint) != 0 || (metaAttrs & (uint)FileAttributes.Directory) != 0)
        {
            throw new Exception("Committed canonical workspace metadata is unavailable or linked");
        }
        var metaInfo = new FileInfo(metadataPath);
        if (metaInfo.Length <= 0 || metaInfo.Length > 1024 * 1024)
        {
            throw new Exception("Committed canonical workspace metadata size is invalid");
        }
        WorkspaceMeta meta = serializer.Deserialize<WorkspaceMeta>(File.ReadAllText(metadataPath, Encoding.UTF8));
        if (meta == null || meta.version != 1 || String.IsNullOrEmpty(meta.sourceDirectory) ||
            !String.Equals(meta.rootKey, rootKey, StringComparison.Ordinal) ||
            !String.Equals(ComputeWorkspaceRootKey(meta.sourceDirectory), rootKey, StringComparison.Ordinal))
        {
            throw new Exception("Committed canonical workspace metadata identity mismatch");
        }
        WorkspaceLpacMeta lpac = meta.windowsLpac;
        if (lpac == null || lpac.version != 1 || String.IsNullOrEmpty(lpac.capabilityNonce) ||
            !String.Equals(lpac.capabilityNonce, lease.capabilityNonce, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(lpac.readCapabilitySid, lease.readCapabilitySid, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(lpac.modifyCapabilitySid, lease.modifyCapabilitySid, StringComparison.OrdinalIgnoreCase) ||
            !IsValidUint32(lpac.volume) || !IsValidUint32(lpac.fileIndexHigh) || !IsValidUint32(lpac.fileIndexLow) ||
            (uint)lpac.volume.Value != lease.grants[0].volume ||
            (uint)lpac.fileIndexHigh.Value != lease.grants[0].fileIndexHigh ||
            (uint)lpac.fileIndexLow.Value != lease.grants[0].fileIndexLow ||
            !String.Equals(lpac.nativeDaclSha256, lease.nativeDaclSha256, StringComparison.Ordinal))
        {
            throw new Exception("Committed canonical workspace metadata does not match initialization lease");
        }
    }

    static void WriteQuarantineEvidenceFile(string evidenceFile, Lease lease, McpCustodyLease custody, string quarantineFile, string reason, JavaScriptSerializer serializer)
    {
        var evidence = new Dictionary<string, object>();
        evidence["version"] = 1;
        evidence["reason"] = reason;
        evidence["quarantinedAt"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        evidence["leaseVersion"] = lease.version;
        evidence["leaseNonce"] = lease.nonce;
        evidence["leasePhase"] = lease.phase;
        evidence["executionId"] = custody.executionId;
        evidence["originalCopyPath"] = lease.cwd;
        evidence["originalSourcePath"] = custody.sourcePath;
        evidence["quarantinedPath"] = quarantineFile;
        evidence["volume"] = custody.volume;
        evidence["fileIndexHigh"] = custody.fileIndexHigh;
        evidence["fileIndexLow"] = custody.fileIndexLow;
        evidence["bytes"] = custody.bytes;
        evidence["sha256"] = custody.sha256;
        evidence["originalDaclBase64"] = custody.originalDaclBase64;
        evidence["originalDaclSha256"] = custody.originalDaclSha256;
        evidence["custodyDaclSha256"] = custody.custodyDaclSha256;
        byte[] evidenceBytes = new UTF8Encoding(false).GetBytes(serializer.Serialize(evidence));
        using (var stream = new FileStream(evidenceFile, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Write(evidenceBytes, 0, evidenceBytes.Length);
            stream.Flush(true);
        }
    }

    static void QuarantineVerifiedMcpCustody(Lease lease, string canonicalState, SecurityIdentifier controllerUser, McpCustodyHold hold, string reason, JavaScriptSerializer serializer)
    {
        McpCustodyLease custody = lease.mcpCustody;
        if (custody == null) return;
        RawSecurityDescriptor originalDacl = ParseValidatedLeaseDacl(custody.originalDaclBase64, custody.originalDaclSha256, "original");
        RawSecurityDescriptor custodyDacl = ParseValidatedLeaseDacl(custody.custodyDaclBase64, custody.custodyDaclSha256, "custody");
        ValidateMonotonicCustodyDacl(originalDacl, custodyDacl, controllerUser);

        Guid leaseNonce = Guid.ParseExact(lease.nonce, "D");
        string quarantineRoot = EnsureProtectedQuarantineRoot(canonicalState, controllerUser);
        string quarantineSlot = Path.Combine(quarantineRoot, leaseNonce.ToString("N"));
        string quarantineFile = Path.Combine(quarantineSlot, "mcp_config.json");
        string evidenceFile = Path.Combine(quarantineSlot, "evidence.json");

        PinnedTarget slotPin = null;
        IntPtr fileHandle = hold != null ? hold.fileHandle : IntPtr.Zero;
        IntPtr quarantineSlotHandle = IntPtr.Zero;
        bool openedFileHere = false;
        bool quarantineSlotCreated = false;
        try
        {
            PinAndVerifyDirectoryNoReparse(custody.custodyDirectory, custody.custodyDirVolume, custody.custodyDirFileIndexHigh, custody.custodyDirFileIndexLow, "Custody slot directory", out slotPin);
            if (fileHandle == IntPtr.Zero || fileHandle == InvalidHandle)
            {
                fileHandle = CreateFile(custody.custodyPath, RequiredCustodyFileAccess, 0, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
                if (fileHandle == InvalidHandle) Check(false, "Open held managed MCP config exclusively for quarantine");
                openedFileHere = true;
            }

            VerifyHandleMatchesCustody(fileHandle, custody, custody.custodyPath);
            RawSecurityDescriptor heldDacl = ReadKernelDacl(fileHandle);
            if (SameDacl(originalDacl, heldDacl) && !SameDacl(custodyDacl, heldDacl))
            {
                WriteKernelDaclExact(fileHandle, custodyDacl);
            }
            else if (!SameDacl(custodyDacl, heldDacl))
            {
                throw new Exception("Held managed MCP config DACL does not match recorded custody DACL");
            }
            ValidateMonotonicCustodyDacl(originalDacl, ReadKernelDacl(fileHandle), controllerUser);

            CreateDirectoryWithProtectedDacl(quarantineSlot, controllerUser, false);
            quarantineSlotCreated = true;
            quarantineSlotHandle = CreateFile(quarantineSlot, StandardRightsRead | StandardRightsWriteDac, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (quarantineSlotHandle == InvalidHandle) Check(false, "Pin exclusive quarantine slot directory");
            ByHandleFileInformation qInfo;
            Check(GetFileInformationByHandle(quarantineSlotHandle, out qInfo), "Inspect exclusive quarantine slot directory");
            if ((qInfo.attributes & (uint)FileAttributes.Directory) == 0 || (qInfo.attributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                throw new Exception("Exclusive quarantine slot directory is invalid or linked");
            }
            if (!String.Equals(FinalPathByHandle(quarantineSlotHandle), quarantineSlot, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Exclusive quarantine slot directory canonical path mismatch");
            }
            if (!IsProtectedControllerDacl(ReadKernelDacl(quarantineSlotHandle), controllerUser, true))
            {
                EnforceProtectedControllerDaclByHandle(quarantineSlotHandle, controllerUser, true);
            }
            if (qInfo.volume != custody.volume)
            {
                throw new Exception("Managed MCP config custody file and quarantine directory are on different volumes");
            }
            if (GetFileAttributes(quarantineFile) != InvalidFileAttributes || Marshal.GetLastWin32Error() != 2)
            {
                throw new Exception("Quarantine destination already exists or is inaccessible");
            }

            RenameHandleNoReplace(fileHandle, quarantineFile);
            if (!String.Equals(FinalPathByHandle(fileHandle), quarantineFile, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Quarantined managed MCP config did not land at expected destination");
            }
            quarantineSlotCreated = false;
            WriteQuarantineEvidenceFile(evidenceFile, lease, custody, quarantineFile, reason, serializer);

            if (openedFileHere)
            {
                CloseHandle(fileHandle);
                fileHandle = IntPtr.Zero;
                openedFileHere = false;
            }
            else if (hold != null)
            {
                CloseHandle(hold.fileHandle);
                hold.fileHandle = IntPtr.Zero;
                fileHandle = IntPtr.Zero;
            }
            CloseHandle(quarantineSlotHandle);
            quarantineSlotHandle = IntPtr.Zero;
            if (slotPin != null) { slotPin.Dispose(); slotPin = null; }
            if (hold != null)
            {
                IntPtr ownedSlot = hold.slotDirHandle;
                hold.slotDirHandle = IntPtr.Zero;
                DeleteVerifiedEmptyCustodySlot(custody, ownedSlot);
            }
            else
            {
                DeleteVerifiedEmptyCustodySlot(custody, IntPtr.Zero);
            }
        }
        finally
        {
            if (openedFileHere && fileHandle != IntPtr.Zero && fileHandle != InvalidHandle) CloseHandle(fileHandle);
            if (quarantineSlotHandle != IntPtr.Zero && quarantineSlotHandle != InvalidHandle) CloseHandle(quarantineSlotHandle);
            if (quarantineSlotCreated) { try { Directory.Delete(quarantineSlot, false); } catch { } }
            if (slotPin != null) slotPin.Dispose();
            if (hold != null) hold.Dispose();
        }
    }

    static McpCustodyOutcome RestoreOrQuarantineMcpConfigCustody(Lease lease, string canonicalState, SecurityIdentifier controllerUser, McpCustodyHold hold, JavaScriptSerializer serializer, out string quarantineReason)
    {
        quarantineReason = null;
        if (lease == null || lease.mcpCustody == null) return McpCustodyOutcome.Restored;
        McpCustodyLease custody = lease.mcpCustody;
        RawSecurityDescriptor originalDacl = ParseValidatedLeaseDacl(custody.originalDaclBase64, custody.originalDaclSha256, "original");
        RawSecurityDescriptor custodyDacl = ParseValidatedLeaseDacl(custody.custodyDaclBase64, custody.custodyDaclSha256, "custody");
        ValidateMonotonicCustodyDacl(originalDacl, custodyDacl, controllerUser);

        string fullCwd = CanonicalLocalPath(lease.cwd, "Workspace copy");
        Guid leaseNonce = Guid.ParseExact(lease.nonce, "D");
        PinnedTarget localCopyPin = null, localAgentsPin = null, slotPin = null;
        IntPtr localCopyDirHandle = IntPtr.Zero, localAgentsDirHandle = IntPtr.Zero;
        IntPtr fileHandle = hold != null ? hold.fileHandle : IntPtr.Zero;
        bool openedFileHere = false;
        try
        {
            // Crash reconciliation when the held file is no longer at custodyPath (already quarantined or never moved / already restored).
            if (fileHandle == IntPtr.Zero || fileHandle == InvalidHandle)
            {
                uint custodyAttrs = GetFileAttributes(custody.custodyPath);
                if (custodyAttrs == InvalidFileAttributes)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 2 || err == 3)
                    {
                        string quarantineSlot = Path.Combine(Path.Combine(canonicalState, "windows-lpac-custody-quarantine"), leaseNonce.ToString("N"));
                        string quarantineFile = Path.Combine(quarantineSlot, "mcp_config.json");
                        string evidenceFile = Path.Combine(quarantineSlot, "evidence.json");
                        if (GetFileAttributes(quarantineFile) != InvalidFileAttributes)
                        {
                            IntPtr existingQuarantine = CreateFile(quarantineFile, RequiredCustodyFileAccess, 0, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
                            if (existingQuarantine == InvalidHandle) Check(false, "Open previously quarantined managed MCP config");
                            try
                            {
                                VerifyHandleMatchesCustody(existingQuarantine, custody, quarantineFile);
                                if (!SameDacl(custodyDacl, ReadKernelDacl(existingQuarantine)))
                                {
                                    throw new Exception("Quarantined managed MCP config DACL mismatch");
                                }
                            }
                            finally { CloseHandle(existingQuarantine); }
                            uint evidenceAttrs = GetFileAttributes(evidenceFile);
                            if (evidenceAttrs == InvalidFileAttributes)
                            {
                                if (Marshal.GetLastWin32Error() != 2) throw new Exception("Quarantined managed MCP config evidence manifest is inaccessible");
                                WriteQuarantineEvidenceFile(evidenceFile, lease, custody, quarantineFile, "previously-quarantined", serializer);
                            }
                            else if ((evidenceAttrs & (uint)FileAttributes.ReparsePoint) != 0 || (evidenceAttrs & (uint)FileAttributes.Directory) != 0)
                            {
                                throw new Exception("Quarantined managed MCP config evidence manifest is invalid or linked");
                            }
                            DeleteVerifiedEmptyCustodySlot(custody, IntPtr.Zero);
                            quarantineReason = "previously-quarantined";
                            return McpCustodyOutcome.Quarantined;
                        }

                        PinAndVerifyDirectoryNoReparse(fullCwd, custody.copyVolume, custody.copyFileIndexHigh, custody.copyFileIndexLow, "Workspace copy parent", out localCopyPin);
                        localCopyDirHandle = OpenCustodyPinnedDirectoryHandle(fullCwd, custody.copyVolume, custody.copyFileIndexHigh, custody.copyFileIndexLow, "Workspace copy parent");
                        PinAndVerifyDirectoryNoReparse(custody.agentsPath, custody.agentsVolume, custody.agentsFileIndexHigh, custody.agentsFileIndexLow, "Managed .agents parent", out localAgentsPin);
                        localAgentsDirHandle = OpenCustodyPinnedDirectoryHandle(custody.agentsPath, custody.agentsVolume, custody.agentsFileIndexHigh, custody.agentsFileIndexLow, "Managed .agents parent");
                        IntPtr srcHandle = CreateFile(custody.sourcePath, RequiredCustodyFileAccess, 0, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
                        if (srcHandle == InvalidHandle) throw new Exception("Managed MCP config is missing from custody, quarantine, and workspace");
                        try
                        {
                            VerifyHandleMatchesCustody(srcHandle, custody, custody.sourcePath);
                            RawSecurityDescriptor currentSrcDacl = ReadKernelDacl(srcHandle);
                            if (SameDacl(custodyDacl, currentSrcDacl) && !SameDacl(originalDacl, currentSrcDacl))
                            {
                                WriteKernelDaclExact(srcHandle, originalDacl);
                            }
                            else if (!SameDacl(originalDacl, currentSrcDacl))
                            {
                                throw new Exception("Managed MCP config DACL at workspace path does not match recorded original or custody DACL");
                            }
                        }
                        finally { CloseHandle(srcHandle); }
                        DeleteVerifiedEmptyCustodySlot(custody, IntPtr.Zero);
                        return McpCustodyOutcome.Restored;
                    }
                    throw new Win32Exception(err, "Inspect held managed MCP config");
                }
            }

            // Positively classify missing owned copy, changed/missing parent, or occupied restore destination.
            // Uncertain Win32 errors (e.g., access denied, linked ancestors) throw and fail closed.
            if (IsOwnedCopyPositivelyMissing(lease, canonicalState))
            {
                QuarantineVerifiedMcpCustody(lease, canonicalState, controllerUser, hold, "owned-copy-missing", serializer);
                hold = null;
                quarantineReason = "owned-copy-missing";
                return McpCustodyOutcome.Quarantined;
            }

            string copyParentDir = Path.GetDirectoryName(fullCwd);
            if (!String.IsNullOrEmpty(copyParentDir))
            {
                using (var ancestorPin = new PinnedTarget { grant = new Grant { rights = "read" }, maxFiles = 1 })
                {
                    ValidatePathComponents(copyParentDir, ancestorPin, false, 1);
                    if (!ancestorPin.grant.directory) throw new Exception("Workspace copy ancestor is not a directory");
                }
            }

            string conflictReason;
            if (!TryInspectDirectoryForRestore(fullCwd, custody.copyVolume, custody.copyFileIndexHigh, custody.copyFileIndexLow, "owned-copy-missing", "copy-parent-changed", out conflictReason))
            {
                if (conflictReason == "owned-copy-missing" && !IsOwnedCopyPositivelyMissing(lease, canonicalState))
                {
                    throw new Exception("Unable to positively verify missing owned workspace copy");
                }
                QuarantineVerifiedMcpCustody(lease, canonicalState, controllerUser, hold, conflictReason, serializer);
                hold = null;
                quarantineReason = conflictReason;
                return McpCustodyOutcome.Quarantined;
            }
            if (hold == null || hold.copyPin == null)
            {
                PinAndVerifyDirectoryNoReparse(fullCwd, custody.copyVolume, custody.copyFileIndexHigh, custody.copyFileIndexLow, "Workspace copy parent", out localCopyPin);
            }
            if (hold == null || hold.copyDirHandle == IntPtr.Zero || hold.copyDirHandle == InvalidHandle)
            {
                localCopyDirHandle = OpenCustodyPinnedDirectoryHandle(fullCwd, custody.copyVolume, custody.copyFileIndexHigh, custody.copyFileIndexLow, "Workspace copy parent");
            }

            if (!TryInspectDirectoryForRestore(custody.agentsPath, custody.agentsVolume, custody.agentsFileIndexHigh, custody.agentsFileIndexLow, "agents-parent-missing", "agents-parent-changed", out conflictReason))
            {
                QuarantineVerifiedMcpCustody(lease, canonicalState, controllerUser, hold, conflictReason, serializer);
                hold = null;
                quarantineReason = conflictReason;
                return McpCustodyOutcome.Quarantined;
            }
            if (hold == null || hold.agentsPin == null)
            {
                PinAndVerifyDirectoryNoReparse(custody.agentsPath, custody.agentsVolume, custody.agentsFileIndexHigh, custody.agentsFileIndexLow, "Managed .agents parent", out localAgentsPin);
            }
            if (hold == null || hold.agentsDirHandle == IntPtr.Zero || hold.agentsDirHandle == InvalidHandle)
            {
                localAgentsDirHandle = OpenCustodyPinnedDirectoryHandle(custody.agentsPath, custody.agentsVolume, custody.agentsFileIndexHigh, custody.agentsFileIndexLow, "Managed .agents parent");
            }

            uint dstAttrs = GetFileAttributes(custody.sourcePath);
            if (dstAttrs != InvalidFileAttributes)
            {
                QuarantineVerifiedMcpCustody(lease, canonicalState, controllerUser, hold, "restore-destination-occupied", serializer);
                hold = null;
                quarantineReason = "restore-destination-occupied";
                return McpCustodyOutcome.Quarantined;
            }
            int dstErr = Marshal.GetLastWin32Error();
            if (dstErr != 2)
            {
                throw new Win32Exception(dstErr, "Inspect managed MCP config restore destination");
            }

            PinAndVerifyDirectoryNoReparse(custody.custodyDirectory, custody.custodyDirVolume, custody.custodyDirFileIndexHigh, custody.custodyDirFileIndexLow, "Custody slot directory", out slotPin);
            if (fileHandle == IntPtr.Zero || fileHandle == InvalidHandle)
            {
                fileHandle = CreateFile(custody.custodyPath, RequiredCustodyFileAccess, 0, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
                if (fileHandle == InvalidHandle) Check(false, "Open held managed MCP config exclusively by handle");
                openedFileHere = true;
            }

            VerifyHandleMatchesCustody(fileHandle, custody, custody.custodyPath);
            RawSecurityDescriptor heldDacl = ReadKernelDacl(fileHandle);
            bool validHeldDacl = SameDacl(custodyDacl, heldDacl) || (hold == null && SameDacl(originalDacl, heldDacl));
            if (!validHeldDacl)
            {
                throw new Exception("Managed MCP config DACL in custody does not match recorded tightened DACL");
            }

            try
            {
                RenameHandleNoReplace(fileHandle, custody.sourcePath);
            }
            catch (Win32Exception renameErr)
            {
                if (renameErr.NativeErrorCode == 183 || renameErr.NativeErrorCode == 80)
                {
                    if (openedFileHere)
                    {
                        CloseHandle(fileHandle);
                        fileHandle = IntPtr.Zero;
                        openedFileHere = false;
                    }
                    if (slotPin != null) { slotPin.Dispose(); slotPin = null; }
                    QuarantineVerifiedMcpCustody(lease, canonicalState, controllerUser, hold, "restore-destination-occupied", serializer);
                    hold = null;
                    quarantineReason = "restore-destination-occupied";
                    return McpCustodyOutcome.Quarantined;
                }
                throw;
            }
            if (!String.Equals(FinalPathByHandle(fileHandle), custody.sourcePath, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Managed MCP config restore did not land at expected workspace path");
            }
            if (!SameDacl(originalDacl, ReadKernelDacl(fileHandle)))
            {
                WriteKernelDaclExact(fileHandle, originalDacl);
            }
            if (!SameDacl(originalDacl, ReadKernelDacl(fileHandle)))
            {
                throw new Exception("Managed MCP config original DACL confirmation by handle failed");
            }

            if (openedFileHere)
            {
                CloseHandle(fileHandle);
                fileHandle = IntPtr.Zero;
                openedFileHere = false;
            }
            else if (hold != null)
            {
                CloseHandle(hold.fileHandle);
                hold.fileHandle = IntPtr.Zero;
                fileHandle = IntPtr.Zero;
            }

            if (slotPin != null) { slotPin.Dispose(); slotPin = null; }
            if (hold != null)
            {
                IntPtr ownedSlot = hold.slotDirHandle;
                hold.slotDirHandle = IntPtr.Zero;
                DeleteVerifiedEmptyCustodySlot(custody, ownedSlot);
            }
            else
            {
                DeleteVerifiedEmptyCustodySlot(custody, IntPtr.Zero);
            }
            return McpCustodyOutcome.Restored;
        }
        finally
        {
            if (openedFileHere && fileHandle != IntPtr.Zero && fileHandle != InvalidHandle) CloseHandle(fileHandle);
            if (slotPin != null) slotPin.Dispose();
            if (localAgentsDirHandle != IntPtr.Zero && localAgentsDirHandle != InvalidHandle) CloseHandle(localAgentsDirHandle);
            if (localCopyDirHandle != IntPtr.Zero && localCopyDirHandle != InvalidHandle) CloseHandle(localCopyDirHandle);
            if (localAgentsPin != null) localAgentsPin.Dispose();
            if (localCopyPin != null) localCopyPin.Dispose();
            if (hold != null) hold.Dispose();
        }
    }

    static void InitWorkspace(Request request, Dictionary<string, object> result, JavaScriptSerializer serializer)
    {
        Guid nonce; if (!Guid.TryParseExact(request.nonce, "D", out nonce)) throw new Exception("Invalid nonce");
        Guid capNonce; if (String.IsNullOrEmpty(request.capabilityNonce) || !Guid.TryParseExact(request.capabilityNonce, "D", out capNonce)) throw new Exception("Invalid capability nonce");
        if (request.maxFiles < 1 || request.maxFiles > 1000000) throw new Exception("Invalid maxFiles");
        if (request.ownerPid < 0) throw new Exception("Invalid workspace initialization owner PID");
        ValidateMcpCustodyRequest(request.mcpCustody);
        long ownerStarted = 0;
        if (request.ownerPid > 0)
        {
            ownerStarted = ActiveProcessStart(request.ownerPid, "workspace initialization owner");
            if (ownerStarted <= 0) throw new Exception("Invalid workspace initialization owner start time");
        }
        result["nonce"] = request.nonce;
        CanonicalWorkspaceInfo ws = ValidateCanonicalWorkspaceCopy(request.cwd, request.stateDirectory, serializer, false);
        if (ws.meta.windowsLpac != null && !String.IsNullOrEmpty(ws.meta.windowsLpac.capabilityNonce))
        {
            throw new Exception("Canonical workspace LPAC permissions are already initialized");
        }
        SecurityIdentifier readSid = DeriveNamedCapabilitySid(WorkspaceCapabilityName(ws.rootKey, capNonce, false));
        SecurityIdentifier modifySid = DeriveNamedCapabilitySid(WorkspaceCapabilityName(ws.rootKey, capNonce, true));
        if (readSid.Equals(modifySid)) throw new Exception("Derived workspace capability SIDs must be distinct");

        string canonicalState = CanonicalLocalPath(request.stateDirectory, "State directory");
        string leaseDir = StateLeaseDirectory(request.stateDirectory);
        string leaseFile = Path.Combine(leaseDir, nonce.ToString("N") + ".json");
        ControllerIdentity controller = CurrentControllerIdentity();
        PinnedTarget readPin = null, modifyPin = null;
        McpCustodyHold initHold = null;
        Lease lease = null;
        bool readApplied = false, modifyApplied = false, holdCreated = false, leaseWritten = false;
        try
        {
            readPin = PinGrant(new Grant { path = ws.copyPath, rights = "read" }, request.maxFiles);
            modifyPin = PinGrant(new Grant { path = ws.copyPath, rights = "modify" }, request.maxFiles);
            if (!SameIdentity(readPin.grant, modifyPin.grant)) throw new Exception("Canonical workspace identity changed during initialization");

            lease = new Lease
            {
                version = request.mcpCustody != null ? 6 : 4,
                nonce = request.nonce,
                phase = "init-workspace",
                controllerPid = Process.GetCurrentProcess().Id,
                controllerStarted = CurrentProcessStart(),
                ownerPid = request.ownerPid,
                ownerStarted = ownerStarted,
                cwd = ws.copyPath,
                grants = new Grant[] { readPin.grant },
                capabilityNonce = capNonce.ToString("D"),
                readCapabilitySid = readSid.Value,
                modifyCapabilitySid = modifySid.Value,
            };

            if (request.mcpCustody != null)
            {
                initHold = AcquireMcpConfigCustody(request.mcpCustody, ws.copyPath, canonicalState, nonce, controller, lease, leaseFile, ref leaseWritten, serializer);
            }

            ValidateCanonicalWorkspaceDacl(readPin, null, null, null, false, request.maxFiles);

            if (!leaseWritten)
            {
                WriteLease(leaseFile, lease, true, serializer);
                leaseWritten = true;
            }

            readApplied = true;
            Access(readPin, readSid, true);
            modifyApplied = true;
            Access(modifyPin, modifySid, true);

            string nativeDigest = ValidateCanonicalWorkspaceDacl(readPin, readSid, modifySid, null, true, request.maxFiles);
            if (lease.ownerPid > 0)
            {
                CreateLeaseHold(leaseFile);
                holdCreated = true;
            }
            lease.phase = "prepared";
            lease.nativeDaclSha256 = nativeDigest;
            WriteLease(leaseFile, lease, false, serializer);

            result["volume"] = readPin.grant.volume;
            result["fileIndexHigh"] = readPin.grant.fileIndexHigh;
            result["fileIndexLow"] = readPin.grant.fileIndexLow;
            result["readCapabilitySid"] = readSid.Value;
            result["modifyCapabilitySid"] = modifySid.Value;
            result["nativeDaclSha256"] = nativeDigest;
        }
        catch (Exception error)
        {
            var cleanupFailures = new List<string>();
            if (holdCreated && leaseFile != null)
            {
                try { DeleteLeaseHoldIfPresent(leaseFile); }
                catch (Exception holdError) { cleanupFailures.Add("Hold: " + holdError.Message); }
            }
            if (modifyApplied && modifyPin != null)
            {
                try { Access(modifyPin, modifySid, false); }
                catch (Exception revokeError) { cleanupFailures.Add("Modify capability revoke: " + revokeError.Message); }
            }
            if (readApplied && readPin != null)
            {
                try { Access(readPin, readSid, false); }
                catch (Exception revokeError) { cleanupFailures.Add("Read capability revoke: " + revokeError.Message); }
            }
            if (cleanupFailures.Count == 0 && leaseWritten && lease != null && lease.mcpCustody != null)
            {
                try
                {
                    string qReason;
                    McpCustodyOutcome outcome = RestoreOrQuarantineMcpConfigCustody(lease, canonicalState, controller.user, initHold, serializer, out qReason);
                    initHold = null;
                    if (outcome == McpCustodyOutcome.Quarantined)
                    {
                        error = new Exception(CombineDiagnostic(error.Message, "MCP config restore conflict (" + qReason + "); verified original preserved in secure bridge quarantine"));
                    }
                }
                catch (Exception restoreError) { cleanupFailures.Add("MCP config custody: " + restoreError.Message); }
            }
            if (initHold != null) { initHold.Dispose(); initHold = null; }
            if (leaseWritten && leaseFile != null)
            {
                if (cleanupFailures.Count == 0)
                {
                    try { File.Delete(leaseFile); }
                    catch (Exception deleteError) { cleanupFailures.Add("Lease: " + deleteError.Message); }
                }
                else if (lease != null)
                {
                    try { lease.phase = "cleanup-failed"; WriteLease(leaseFile, lease, false, serializer); }
                    catch (Exception writeError) { cleanupFailures.Add("Lease: " + writeError.Message); }
                }
            }
            string combined = cleanupFailures.Count == 0 ? error.Message : CombineDiagnostic(error.Message, "Rollback failed: " + String.Join("; ", cleanupFailures.ToArray()));
            throw new Exception(combined);
        }
        finally
        {
            if (initHold != null) { initHold.Dispose(); initHold = null; }
            if (modifyPin != null) modifyPin.Dispose();
            if (readPin != null) readPin.Dispose();
        }
    }

    enum WorkspaceInitCommitState
    {
        NotCommitted,
        Committed,
        Inconclusive,
    }

    static string LeaseHoldFile(string leaseFile)
    {
        return Path.ChangeExtension(leaseFile, ".hold");
    }

    static void CreateLeaseHold(string leaseFile)
    {
        string holdFile = LeaseHoldFile(leaseFile);
        using (var stream = new FileStream(holdFile, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Flush(true);
        }
    }

    static void DeleteLeaseHoldIfPresent(string leaseFile)
    {
        string holdFile = LeaseHoldFile(leaseFile);
        uint attrs = GetFileAttributes(holdFile);
        if (attrs == InvalidFileAttributes)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 2 || error == 3) return;
            throw new Win32Exception(error, "Inspect workspace initialization hold");
        }
        if ((attrs & (uint)FileAttributes.ReparsePoint) != 0 || (attrs & (uint)FileAttributes.Directory) != 0)
        {
            throw new Exception("Workspace initialization hold is linked or invalid");
        }
        File.Delete(holdFile);
    }

    static bool LeaseFileExists(string leaseFile)
    {
        uint attrs = GetFileAttributes(leaseFile);
        if (attrs != InvalidFileAttributes) return true;
        int error = Marshal.GetLastWin32Error();
        if (error == 2 || error == 3) return false;
        throw new Win32Exception(error, "Inspect lease file");
    }

    static bool ReferencesLeaseGrant(WorkspaceLpacMeta lpac, Lease lease)
    {
        if (lpac == null) return false;
        if (!String.IsNullOrEmpty(lpac.capabilityNonce) &&
            String.Equals(lpac.capabilityNonce, lease.capabilityNonce, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (!String.IsNullOrEmpty(lpac.readCapabilitySid) &&
            (String.Equals(lpac.readCapabilitySid, lease.readCapabilitySid, StringComparison.OrdinalIgnoreCase) ||
             String.Equals(lpac.readCapabilitySid, lease.modifyCapabilitySid, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }
        if (!String.IsNullOrEmpty(lpac.modifyCapabilitySid) &&
            (String.Equals(lpac.modifyCapabilitySid, lease.modifyCapabilitySid, StringComparison.OrdinalIgnoreCase) ||
             String.Equals(lpac.modifyCapabilitySid, lease.readCapabilitySid, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }
        return false;
    }

    static CanonicalWorkspaceInfo ValidateCommittedWorkspaceMetadata(Lease lease, string stateDirectory, JavaScriptSerializer serializer)
    {
        Guid capNonce;
        if (lease == null || String.IsNullOrEmpty(lease.capabilityNonce) || !Guid.TryParseExact(lease.capabilityNonce, "D", out capNonce) ||
            lease.grants == null || lease.grants.Length != 1 || lease.grants[0] == null || !IsLowerHex(lease.nativeDaclSha256, 64))
        {
            throw new Exception("Committed workspace initialization lease is incomplete");
        }
        CanonicalWorkspaceInfo ws = ValidateCanonicalWorkspaceCopy(lease.cwd, stateDirectory, serializer, true);
        if (!ws.capabilityNonce.Equals(capNonce))
        {
            throw new Exception("Canonical workspace LPAC capability nonce mismatch");
        }
        if (!String.Equals(ws.readSid.Value, lease.readCapabilitySid, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(ws.modifySid.Value, lease.modifyCapabilitySid, StringComparison.OrdinalIgnoreCase))
        {
            throw new Exception("Canonical workspace LPAC capability SID mismatch");
        }
        if ((uint)ws.meta.windowsLpac.volume.Value != lease.grants[0].volume ||
            (uint)ws.meta.windowsLpac.fileIndexHigh.Value != lease.grants[0].fileIndexHigh ||
            (uint)ws.meta.windowsLpac.fileIndexLow.Value != lease.grants[0].fileIndexLow ||
            !String.Equals(ws.meta.windowsLpac.nativeDaclSha256, lease.nativeDaclSha256, StringComparison.Ordinal))
        {
            throw new Exception("Canonical workspace LPAC pin identity or DACL digest mismatch");
        }
        return ws;
    }

    static WorkspaceInitCommitState InspectWorkspaceInitCommit(Lease lease, string stateDirectory, JavaScriptSerializer serializer, out string reason)
    {
        reason = null;
        if (lease == null || !IsInitLeaseVersion(lease.version) || lease.phase != "prepared")
        {
            reason = "Lease is not a prepared workspace initialization lease";
            return WorkspaceInitCommitState.NotCommitted;
        }
        Guid capNonce;
        if (String.IsNullOrEmpty(lease.capabilityNonce) || !Guid.TryParseExact(lease.capabilityNonce, "D", out capNonce) ||
            !IsLowerHex(lease.nativeDaclSha256, 64) ||
            lease.grants == null || lease.grants.Length != 1 || lease.grants[0] == null)
        {
            reason = "Prepared workspace initialization lease is incomplete";
            return WorkspaceInitCommitState.Inconclusive;
        }
        string fullCopy, rootKey, metadataPath;
        if (!TryGetCanonicalWorkspaceRootKey(lease.cwd, stateDirectory, out fullCopy, out rootKey, out metadataPath))
        {
            reason = "Prepared workspace lease target is not a canonical workspace copy";
            return WorkspaceInitCommitState.Inconclusive;
        }
        uint metaAttrs = GetFileAttributes(metadataPath);
        if (metaAttrs == InvalidFileAttributes)
        {
            int metaError = Marshal.GetLastWin32Error();
            if (metaError == 2 || metaError == 3)
            {
                return WorkspaceInitCommitState.NotCommitted;
            }
            reason = "Unable to inspect workspace metadata (Win32 " + metaError.ToString() + ")";
            return WorkspaceInitCommitState.Inconclusive;
        }
        if ((metaAttrs & (uint)FileAttributes.ReparsePoint) != 0 || (metaAttrs & (uint)FileAttributes.Directory) != 0)
        {
            reason = "Canonical workspace metadata is linked or not a file";
            return WorkspaceInitCommitState.Inconclusive;
        }
        WorkspaceMeta meta;
        try
        {
            var metaInfo = new FileInfo(metadataPath);
            if (metaInfo.Length <= 0 || metaInfo.Length > 1024 * 1024)
            {
                reason = "Canonical workspace metadata size is invalid";
                return WorkspaceInitCommitState.Inconclusive;
            }
            meta = serializer.Deserialize<WorkspaceMeta>(File.ReadAllText(metadataPath, Encoding.UTF8));
        }
        catch (FileNotFoundException)
        {
            return WorkspaceInitCommitState.NotCommitted;
        }
        catch (DirectoryNotFoundException)
        {
            return WorkspaceInitCommitState.NotCommitted;
        }
        catch (Exception error)
        {
            reason = "Unable to read canonical workspace metadata: " + error.Message;
            return WorkspaceInitCommitState.Inconclusive;
        }
        if (meta == null || meta.version != 1 || String.IsNullOrEmpty(meta.sourceDirectory) ||
            !String.Equals(meta.rootKey, rootKey, StringComparison.Ordinal))
        {
            reason = "Canonical workspace metadata identity mismatch";
            return WorkspaceInitCommitState.Inconclusive;
        }
        try
        {
            if (!String.Equals(ComputeWorkspaceRootKey(meta.sourceDirectory), rootKey, StringComparison.Ordinal))
            {
                reason = "Canonical workspace rootKey does not match sourceDirectory";
                return WorkspaceInitCommitState.Inconclusive;
            }
        }
        catch (Exception error)
        {
            reason = "Unable to validate canonical workspace rootKey: " + error.Message;
            return WorkspaceInitCommitState.Inconclusive;
        }

        WorkspaceLpacMeta lpac = meta.windowsLpac;
        if (lpac == null)
        {
            return WorkspaceInitCommitState.NotCommitted;
        }
        if (!ReferencesLeaseGrant(lpac, lease))
        {
            if (lpac.version != 1)
            {
                reason = "Canonical workspace LPAC metadata version is invalid";
                return WorkspaceInitCommitState.Inconclusive;
            }
            if (!String.IsNullOrEmpty(lpac.capabilityNonce))
            {
                Guid otherNonce;
                if (!Guid.TryParseExact(lpac.capabilityNonce, "D", out otherNonce))
                {
                    reason = "Canonical workspace LPAC capability nonce is invalid";
                    return WorkspaceInitCommitState.Inconclusive;
                }
            }
            return WorkspaceInitCommitState.NotCommitted;
        }

        try
        {
            CanonicalWorkspaceInfo ws = ValidateCommittedWorkspaceMetadata(lease, stateDirectory, serializer);
            using (PinnedTarget pin = PinGrant(new Grant { path = ws.copyPath, rights = "read" }, RevokeFileBudget))
            {
                if (!SameIdentity(lease.grants[0], pin.grant))
                {
                    reason = "Canonical workspace copy identity changed";
                    return WorkspaceInitCommitState.Inconclusive;
                }
                ValidateCanonicalWorkspaceDacl(pin, ws.readSid, ws.modifySid, lease.nativeDaclSha256, true, RevokeFileBudget);
            }
            return WorkspaceInitCommitState.Committed;
        }
        catch (Exception error)
        {
            reason = error.Message;
            return WorkspaceInitCommitState.Inconclusive;
        }
    }

    static void CommitWorkspaceLease(Request request, Dictionary<string, object> result, JavaScriptSerializer serializer)
    {
        Guid nonce; if (!Guid.TryParseExact(request.nonce, "D", out nonce)) throw new Exception("Invalid nonce");
        ValidateMcpCustodyRequest(request.mcpCustody);
        result["nonce"] = request.nonce;
        string canonicalState = CanonicalLocalPath(request.stateDirectory, "State directory");
        string leaseDir = StateLeaseDirectory(request.stateDirectory);
        string leaseFile = Path.Combine(leaseDir, nonce.ToString("N") + ".json");
        if (!File.Exists(leaseFile) || (File.GetAttributes(leaseFile) & FileAttributes.ReparsePoint) != 0)
        {
            throw new Exception("Workspace initialization lease is missing or linked");
        }
        Lease lease = serializer.Deserialize<Lease>(File.ReadAllText(leaseFile, Encoding.UTF8));
        ValidateLease(lease, leaseFile, request.stateDirectory);
        if (!IsInitLeaseVersion(lease.version) || (lease.phase != "prepared" && lease.phase != "committed"))
        {
            throw new Exception("Workspace initialization lease is not in prepared state");
        }
        if (lease.phase == "committed" && lease.version != 6)
        {
            throw new Exception("Only version 6 custody workspace initialization leases may enter committed phase");
        }
        string fullCopy, rootKey, metadataPath;
        if (!TryGetCanonicalWorkspaceRootKey(request.cwd, request.stateDirectory, out fullCopy, out rootKey, out metadataPath) ||
            !String.Equals(lease.cwd, fullCopy, StringComparison.OrdinalIgnoreCase))
        {
            throw new Exception("Workspace initialization lease target mismatch");
        }
        if ((request.mcpCustody == null) != (lease.mcpCustody == null))
        {
            throw new Exception("Workspace initialization lease MCP custody presence mismatch");
        }
        if (request.mcpCustody != null && lease.mcpCustody != null)
        {
            if (!String.Equals(request.mcpCustody.executionId, lease.mcpCustody.executionId, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(request.mcpCustody.sha256, lease.mcpCustody.sha256, StringComparison.Ordinal) ||
                request.mcpCustody.bytes != lease.mcpCustody.bytes)
            {
                throw new Exception("Workspace initialization lease MCP custody identity mismatch");
            }
        }
        if (lease.phase == "prepared")
        {
            string commitReason;
            if (InspectWorkspaceInitCommit(lease, request.stateDirectory, serializer, out commitReason) != WorkspaceInitCommitState.Committed)
            {
                throw new Exception("Workspace LPAC pin is not durably committed or does not match prepared lease" + (String.IsNullOrEmpty(commitReason) ? "" : ": " + commitReason));
            }
            if (lease.mcpCustody != null)
            {
                lease.phase = "committed";
                WriteLease(leaseFile, lease, false, serializer);
            }
        }
        else
        {
            ValidateCommittedLeaseMetadataFile(lease, request.stateDirectory, canonicalState, serializer);
        }
        if (lease.mcpCustody != null)
        {
            ControllerIdentity controller = CurrentControllerIdentity();
            string qReason;
            McpCustodyOutcome outcome = RestoreOrQuarantineMcpConfigCustody(lease, canonicalState, controller.user, null, serializer, out qReason);
            File.Delete(leaseFile);
            DeleteLeaseHoldIfPresent(leaseFile);
            if (outcome == McpCustodyOutcome.Quarantined)
            {
                throw new Exception("Managed MCP config restore conflict (" + qReason + "); verified original preserved in secure bridge quarantine");
            }
            result["mcpConfigCustodyRestored"] = true;
            result["committed"] = true;
            return;
        }
        File.Delete(leaseFile);
        DeleteLeaseHoldIfPresent(leaseFile);
        result["committed"] = true;
    }

    // Cloud Files placeholders keep their path identity; links and unknown tags remain forbidden.
    static bool IsCloudTag(uint tag) { return (tag & 0xFFFF0FFF) == 0x9000001A; }

    static void ValidatePathComponents(string full, PinnedTarget target, bool walkTree, int maxFiles, bool isRevoke = false)
    {
        RequireLocalAbsolutePath(full, "Permission target");
        string canonical = Path.GetFullPath(full).TrimEnd(Path.DirectorySeparatorChar);
        if (String.Equals(canonical + Path.DirectorySeparatorChar, Path.GetPathRoot(canonical), StringComparison.OrdinalIgnoreCase)) throw new Exception("Permission target cannot be a volume root");
        string root = Path.GetPathRoot(canonical), tail = canonical.Substring(root.Length), current = root;
        if (tail.Length == 0) throw new Exception("Permission target cannot be a volume root");
        string[] pieces = tail.Split(new char[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
        for (int index = 0; index < pieces.Length; index++)
        {
            current = Path.Combine(current, pieces[index]);
            IntPtr handle = CreateFile(current, 0, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle == InvalidHandle) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open permission target");
            try
            {
                ByHandleFileInformation info; Check(GetFileInformationByHandle(handle, out info), "Inspect permission target");
                bool isReparse = (info.attributes & (uint)FileAttributes.ReparsePoint) != 0;
                bool isCloud = false;
                if (isReparse)
                {
                    FileAttributeTagInfo tagInfo;
                    Check(GetFileInformationByHandleEx(handle, 9, out tagInfo, 8), "Inspect permission target reparse tag");
                    if (IsCloudTag(tagInfo.tag))
                    {
                        isCloud = true;
                    }
                    else
                    {
                        if (!isRevoke || index < pieces.Length - 1) throw new Exception("Permission target contains an unsafe reparse point");
                    }
                }
                bool directory = (info.attributes & (uint)FileAttributes.Directory) != 0;
                if (index < pieces.Length - 1 && !directory) throw new Exception("Permission target component is not a directory");
                if (index == pieces.Length - 1)
                {
                    if (!directory && !isRevoke && info.links > 1) throw new Exception("Permission target file has multiple hard links");
                    if (isRevoke && isReparse && !isCloud) target.revokeLeaf = true;
                    target.grant.path = canonical; target.grant.directory = directory; target.grant.volume = info.volume; target.grant.fileIndexHigh = info.indexHigh; target.grant.fileIndexLow = info.indexLow;
                }
                target.Add(handle); handle = IntPtr.Zero;
            }
            finally { if (handle != IntPtr.Zero && handle != InvalidHandle) CloseHandle(handle); }
        }
        if (walkTree && target.grant.directory) ScanTree(canonical, maxFiles, new int[] { 0 });
    }

    static void ScanTree(string directory, int maxFiles, int[] count)
    {
        foreach (string child in Directory.GetFileSystemEntries(directory))
        {
            if (++count[0] > maxFiles) throw new Exception("Permission directory exceeds the configured file limit");
            var temporary = new PinnedTarget { grant = new Grant { rights = "read" } };
            try { ValidatePathComponents(child, temporary, false, maxFiles); if (temporary.grant.directory) ScanTree(child, maxFiles, count); }
            finally { temporary.Dispose(); }
        }
    }

    static void DiscoverNestedGitRepositories(string rootDirectory, string currentDirectory, int maxFiles, int[] count, List<string> discovered)
    {
        foreach (string child in Directory.GetFileSystemEntries(currentDirectory))
        {
            if (++count[0] > maxFiles) throw new Exception("Copy directory exceeds the configured file limit during repository discovery");
            var temporary = new PinnedTarget { grant = new Grant { rights = "read" } };
            try
            {
                ValidatePathComponents(child, temporary, false, maxFiles);
                if (temporary.grant.directory)
                {
                    string name = Path.GetFileName(child);
                    if (String.Equals(name, ".git", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!String.Equals(currentDirectory, rootDirectory, StringComparison.OrdinalIgnoreCase))
                        {
                            discovered.Add(currentDirectory);
                        }
                    }
                    else
                    {
                        DiscoverNestedGitRepositories(rootDirectory, child, maxFiles, count, discovered);
                    }
                }
            }
            finally { temporary.Dispose(); }
        }
    }

    static PinnedTarget PinGrant(Grant supplied, int maxFiles)
    {
        if (supplied == null || (supplied.rights != "read" && supplied.rights != "modify")) throw new Exception("Invalid permission grant");
        var target = new PinnedTarget { grant = new Grant { path = supplied.path, rights = supplied.rights }, maxFiles = maxFiles };
        try { ValidatePathComponents(supplied.path, target, Directory.Exists(supplied.path), maxFiles); return target; }
        catch { target.Dispose(); throw; }
    }

    static PinnedTarget PinRevokeTarget(Grant supplied, int maxFiles)
    {
        if (supplied == null || (supplied.rights != "read" && supplied.rights != "modify")) throw new Exception("Invalid permission grant");
        var target = new PinnedTarget { grant = new Grant { path = supplied.path, rights = supplied.rights }, maxFiles = maxFiles };
        try { ValidatePathComponents(supplied.path, target, false, maxFiles, true); return target; }
        catch { target.Dispose(); throw; }
    }

    static bool SameIdentity(Grant expected, Grant actual)
    {
        return expected.directory == actual.directory && expected.volume == actual.volume && expected.fileIndexHigh == actual.fileIndexHigh && expected.fileIndexLow == actual.fileIndexLow;
    }

    static FileSystemRights RightsFor(Grant grant) { return grant.rights == "modify" ? FileSystemRights.Modify | FileSystemRights.Synchronize : FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize; }

    static RawSecurityDescriptor ReadDacl(string path)
    {
        uint needed;
        if (!GetFileSecurity(path, 4, null, 0, out needed) && Marshal.GetLastWin32Error() != 122) Check(false, "Measure target DACL");
        if (needed == 0 || needed > 1024 * 1024) throw new Exception("Invalid target DACL size");
        var data = new byte[needed];
        Check(GetFileSecurity(path, 4, data, needed, out needed), "Read target DACL");
        return new RawSecurityDescriptor(data, 0);
    }

    static bool SameDacl(RawSecurityDescriptor expected, RawSecurityDescriptor actual)
    {
        if (expected.ControlFlags != actual.ControlFlags || expected.DiscretionaryAcl == null || actual.DiscretionaryAcl == null || expected.DiscretionaryAcl.BinaryLength != actual.DiscretionaryAcl.BinaryLength) return false;
        var left = new byte[expected.DiscretionaryAcl.BinaryLength]; var right = new byte[actual.DiscretionaryAcl.BinaryLength];
        expected.DiscretionaryAcl.GetBinaryForm(left, 0); actual.DiscretionaryAcl.GetBinaryForm(right, 0);
        for (int index = 0; index < left.Length; index++) if (left[index] != right[index]) return false;
        return true;
    }

    const int RevokeFileBudget = 1000000;

    static void AddCleanupFailure(List<string> failures, string message)
    {
        if (failures.Count > 25 || (failures.Count == 1 && failures[0] == OversizedDiagnosticMessage)) return;
        if (failures.Count == 25) message = "Additional cleanup failures omitted";
        long length = message.Length;
        foreach (string failure in failures) length += failure.Length + 2;
        if (length > MaxDiagnosticCharacters)
        {
            failures.Clear(); failures.Add(OversizedDiagnosticMessage);
        }
        else failures.Add(message);
    }

    static void Access(PinnedTarget target, SecurityIdentifier identity, bool grant)
    {
        if (!grant)
        {
            using (PinnedTarget fresh = PinRevokeTarget(target.grant, RevokeFileBudget))
            {
                if (!SameIdentity(target.grant, fresh.grant)) throw new Exception("Granted target identity changed");
                AccessTree(fresh, identity, false, true, RevokeFileBudget, new int[] { 0 });
            }
            return;
        }
        AccessTree(target, identity, true, true, target.maxFiles, new int[] { 0 });
    }

    static void AccessTree(PinnedTarget target, SecurityIdentifier identity, bool grant, bool root, int maxFiles, int[] count)
    {
        string rootFailure = null;
        try
        {
            // Read the stored descriptor: GetAccessControl infers inherited flags on legacy DACLs.
            RawSecurityDescriptor descriptor = ReadDacl(target.grant.path);
            if (grant && !root && (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0) return;
            RawAcl acl = descriptor.DiscretionaryAcl;
            bool changed = false;
            if (acl == null && grant) throw new Exception("Permission target has no DACL");
            if (acl != null)
            {
                int rights = (int)RightsFor(target.grant); CommonAce existing = null;
                for (int index = acl.Count - 1; index >= 0; index--)
                {
                    KnownAce ace = acl[index] as KnownAce;
                    if (ace == null || !identity.Equals(ace.SecurityIdentifier)) continue;
                    if (!grant) { acl.RemoveAce(index); changed = true; }
                    else
                    {
                        CommonAce allow = ace as CommonAce;
                        if (allow == null || allow.AceQualifier != AceQualifier.AccessAllowed || allow.IsCallback) throw new Exception("Unexpected owned permission rule");
                        existing = allow;
                        if ((allow.AccessMask & rights) != rights) { allow.AccessMask |= rights; changed = true; }
                    }
                }
                if (grant && existing == null)
                {
                    AceFlags flags = target.grant.directory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None;
                    if (!root && (descriptor.ControlFlags & ControlFlags.DiscretionaryAclAutoInherited) != 0) flags |= AceFlags.Inherited;
                    int insert = acl.Count;
                    if ((flags & AceFlags.Inherited) == 0) for (int index = 0; index < acl.Count; index++) if ((acl[index].AceFlags & AceFlags.Inherited) != 0) { insert = index; break; }
                    acl.InsertAce(insert, new CommonAce(flags, AceQualifier.AccessAllowed, rights, identity, false, null)); changed = true;
                }
                if (changed)
                {
                    ControlFlags storedFlags = descriptor.ControlFlags;
                    // AR preserves AI in this non-propagating write; Windows consumes AR.
                    if ((storedFlags & ControlFlags.DiscretionaryAclAutoInherited) != 0) descriptor.SetFlags(storedFlags | ControlFlags.DiscretionaryAclAutoInheritRequired);
                    var data = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(data, 0);
                    Check(SetFileSecurity(target.grant.path, 4, data), "Write target DACL");
                    descriptor.SetFlags(storedFlags);
                    if (!SameDacl(descriptor, ReadDacl(target.grant.path))) throw new Exception("Target DACL update was not preserved exactly");
                }
            }
        }
        catch (Exception error)
        {
            if (grant) throw;
            rootFailure = Path.GetFileName(target.grant.path) + " DACL: " + error.Message;
        }

        // SetFileSecurity preserves stored ACEs but does not propagate to existing children.
        if (!target.grant.directory || (!grant && target.revokeLeaf))
        {
            if (rootFailure != null) throw new Exception(CombineDiagnostic(rootFailure, null));
            return;
        }

        List<string> childFailures = null;
        try
        {
            foreach (string child in Directory.EnumerateFileSystemEntries(target.grant.path))
            {
                if (++count[0] > maxFiles)
                {
                    if (grant) throw new Exception("Permission directory exceeds the configured file limit");
                    if (childFailures == null) childFailures = new List<string>();
                    AddCleanupFailure(childFailures, "Permission directory exceeds cleanup file limit");
                    break;
                }
                using (var pin = new PinnedTarget { grant = new Grant { rights = target.grant.rights }, maxFiles = maxFiles })
                {
                    try
                    {
                        ValidatePathComponents(child, pin, false, maxFiles, !grant);
                        AccessTree(pin, identity, grant, false, maxFiles, count);
                    }
                    catch (Exception error)
                    {
                        if (grant) throw;
                        if (childFailures == null) childFailures = new List<string>();
                        AddCleanupFailure(childFailures, Path.GetFileName(child) + ": " + error.Message);
                    }
                }
            }
        }
        catch (Exception enumError)
        {
            if (grant) throw;
            if (childFailures == null) childFailures = new List<string>();
            AddCleanupFailure(childFailures, "Enumerate: " + enumError.Message);
        }

        var allFailures = new List<string>();
        if (rootFailure != null) AddCleanupFailure(allFailures, rootFailure);
        if (childFailures != null) foreach (string failure in childFailures) AddCleanupFailure(allFailures, failure);
        if (allFailures.Count != 0) throw new Exception(String.Join("; ", allFailures.ToArray()));
    }

    const string NullDeviceKernelPath = @"\\?\GLOBALROOT\Device\Null";
    const uint StandardRightsRead = 0x00020000;
    const uint StandardRightsWriteDac = 0x00040000;
    const int NullDeviceAccessRights = 0x12019f; // FILE_GENERIC_READ | FILE_GENERIC_WRITE union
    static readonly SecurityIdentifier AllRestrictedPackagesSid = new SecurityIdentifier("S-1-15-2-2");
    static readonly SecurityIdentifier WorldSid = new SecurityIdentifier("S-1-1-0");

    sealed class NullDeviceGate : IDisposable
    {
        // The Null device is shared with runners built before the rename, which serialize on the earlier name only.
        // Both mutexes are therefore taken, always in this order, so the two generations never rewrite its DACL at once.
        static readonly string[] MutexNames = { "Global\\BLACK_GRAVITY.TEST.NULL_DEVICE.MUTEX", "Global\\AGY.TEST.NULL_DEVICE.MUTEX" };
        const uint MutexSynchronizeAndModify = 0x00100001; // SYNCHRONIZE | MUTEX_MODIFY_STATE
        readonly IntPtr[] handles = new IntPtr[MutexNames.Length];
        readonly bool[] owned = new bool[MutexNames.Length];

        public static NullDeviceGate Acquire(int timeoutMilliseconds = 30000)
        {
            var gate = new NullDeviceGate();
            try
            {
                for (int index = 0; index < MutexNames.Length; index++)
                {
                    gate.handles[index] = OpenOrCreate(MutexNames[index]);
                    uint wait = WaitForSingleObject(gate.handles[index], checked((uint)timeoutMilliseconds));
                    if (wait == WaitObject0 || wait == 0x80) { gate.owned[index] = true; continue; }
                    if (wait == WaitTimeout) throw new Exception("Null device mutex wait timed out");
                    int err = Marshal.GetLastWin32Error();
                    throw new Win32Exception(err, "Wait for Null device mutex (Win32 " + err + ")");
                }
                return gate;
            }
            catch
            {
                gate.Dispose();
                throw;
            }
        }

        static IntPtr OpenOrCreate(string MutexName)
        {
            IntPtr handle = OpenMutex(MutexSynchronizeAndModify, false, MutexName);
            if (handle != IntPtr.Zero) return handle;
            int err = Marshal.GetLastWin32Error();
            if (err != 2 && err != 1168) throw new Win32Exception(err, "Open Null device mutex (Win32 " + err + ")");

            var security = new MutexSecurity();
            security.AddAccessRule(new MutexAccessRule(WorldSid, MutexRights.Synchronize | MutexRights.Modify, AccessControlType.Allow));
            byte[] sdBytes = security.GetSecurityDescriptorBinaryForm();
            IntPtr pSd = Marshal.AllocHGlobal(sdBytes.Length);
            try
            {
                Marshal.Copy(sdBytes, 0, pSd, sdBytes.Length);
                var sa = new SecurityAttributes { length = Marshal.SizeOf(typeof(SecurityAttributes)), descriptor = pSd, inherit = 0 };
                IntPtr pSa = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityAttributes)));
                try
                {
                    Marshal.StructureToPtr(sa, pSa, false);
                    handle = CreateMutex(pSa, false, MutexName);
                    if (handle == IntPtr.Zero)
                    {
                        int createErr = Marshal.GetLastWin32Error();
                        handle = OpenMutex(MutexSynchronizeAndModify, false, MutexName);
                        if (handle == IntPtr.Zero) throw new Win32Exception(createErr, "Create Null device mutex (Win32 " + createErr + ")");
                    }
                }
                finally { Marshal.FreeHGlobal(pSa); }
            }
            finally { Marshal.FreeHGlobal(pSd); }
            return handle;
        }

        public void Dispose()
        {
            for (int index = handles.Length - 1; index >= 0; index--)
            {
                if (handles[index] == IntPtr.Zero) continue;
                if (owned[index])
                {
                    ReleaseMutex(handles[index]);
                    owned[index] = false;
                }
                CloseHandle(handles[index]);
                handles[index] = IntPtr.Zero;
            }
        }
    }

    internal static RawSecurityDescriptor ReadKernelDacl(IntPtr handle)
    {
        uint needed;
        GetKernelObjectSecurity(handle, 4, null, 0, out needed);
        int err = Marshal.GetLastWin32Error();
        if (err != 0 && err != 122) Check(false, "Measure kernel object DACL");
        if (needed < 20 || needed > 65536) throw new Exception("Invalid kernel object DACL size: " + needed);
        byte[] buffer = new byte[needed];
        Check(GetKernelObjectSecurity(handle, 4, buffer, needed, out needed), "Read kernel object DACL");
        return new RawSecurityDescriptor(buffer, 0);
    }

    internal static void WriteKernelDacl(IntPtr handle, RawSecurityDescriptor descriptor)
    {
        byte[] buffer = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(buffer, 0);
        Check(SetKernelObjectSecurity(handle, 4, buffer), "Write kernel object DACL");
    }

    internal static bool IsStockNullAccessSufficient(RawSecurityDescriptor descriptor, SecurityIdentifier childSid)
    {
        if (descriptor == null || descriptor.DiscretionaryAcl == null) return false;
        RawAcl acl = descriptor.DiscretionaryAcl;
        for (int i = 0; i < acl.Count; i++)
        {
            CommonAce ace = acl[i] as CommonAce;
            if (ace != null && ace.AceQualifier == AceQualifier.AccessDenied)
            {
                if ((ace.SecurityIdentifier.Equals(AllRestrictedPackagesSid) ||
                     ace.SecurityIdentifier.Equals(WorldSid) ||
                     (childSid != null && ace.SecurityIdentifier.Equals(childSid))) &&
                    (ace.AccessMask & NullDeviceAccessRights) != 0)
                {
                    return false;
                }
            }
        }
        for (int i = 0; i < acl.Count; i++)
        {
            CommonAce ace = acl[i] as CommonAce;
            if (ace != null && ace.AceQualifier == AceQualifier.AccessAllowed &&
                !ace.IsCallback && (ace.AceFlags & AceFlags.InheritOnly) == 0 &&
                ace.SecurityIdentifier.Equals(AllRestrictedPackagesSid))
            {
                if ((ace.AccessMask & NullDeviceAccessRights) == NullDeviceAccessRights)
                {
                    return true;
                }
            }
        }
        return false;
    }

    internal static RawSecurityDescriptor ApplyNullDeviceAceToDescriptor(RawSecurityDescriptor descriptor, SecurityIdentifier identity)
    {
        if (descriptor == null || descriptor.DiscretionaryAcl == null) throw new ArgumentNullException("descriptor");
        if (identity == null) throw new ArgumentNullException("identity");
        const ControlFlags supported = ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected | ControlFlags.SelfRelative;
        if ((descriptor.ControlFlags & ~supported) != 0) throw new Exception("Unsupported Null device DACL control flags: 0x" + ((int)descriptor.ControlFlags).ToString("x4"));
        RawAcl acl = descriptor.DiscretionaryAcl;
        for (int i = 0; i < acl.Count; i++)
        {
            CommonAce ace = acl[i] as CommonAce;
            if (ace == null || ace.IsCallback) throw new Exception("Unexpected ACE in Null device DACL");
            if (ace.AceQualifier == AceQualifier.AccessDenied &&
                (ace.SecurityIdentifier.Equals(identity) || ace.SecurityIdentifier.Equals(AllRestrictedPackagesSid) || ace.SecurityIdentifier.Equals(WorldSid)) &&
                (ace.AccessMask & NullDeviceAccessRights) != 0)
            {
                throw new Exception("Explicit deny on Null device DACL prevents execution access");
            }
            if (ace.SecurityIdentifier.Equals(identity))
            {
                throw new Exception("Duplicate or unexpected existing owned ACE for execution SID in Null device DACL");
            }
        }
        var newAce = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, NullDeviceAccessRights, identity, false, null);
        int insertIndex = 0;
        while (insertIndex < acl.Count && ((CommonAce)acl[insertIndex]).AceQualifier == AceQualifier.AccessDenied)
        {
            insertIndex++;
        }
        acl.InsertAce(insertIndex, newAce);
        return descriptor;
    }

    internal static bool RemoveNullDeviceAceFromDescriptor(RawSecurityDescriptor descriptor, SecurityIdentifier identity, bool requirePresent)
    {
        if (descriptor == null || descriptor.DiscretionaryAcl == null) throw new ArgumentNullException("descriptor");
        if (identity == null) throw new ArgumentNullException("identity");
        RawAcl acl = descriptor.DiscretionaryAcl;
        int foundIndex = -1;
        int matchCount = 0;
        for (int i = 0; i < acl.Count; i++)
        {
            CommonAce ace = acl[i] as CommonAce;
            if (ace != null && ace.SecurityIdentifier.Equals(identity))
            {
                matchCount++;
                foundIndex = i;
                if (ace.AceQualifier != AceQualifier.AccessAllowed || ace.AceFlags != AceFlags.None ||
                    ace.AccessMask != NullDeviceAccessRights || ace.IsCallback)
                {
                    throw new Exception("Unexpected owned permission rule on Null device DACL");
                }
            }
        }
        if (matchCount > 1) throw new Exception("Duplicate owned ACEs on Null device DACL for execution SID");
        if (matchCount == 0)
        {
            if (requirePresent) throw new Exception("Expected owned ACE on Null device DACL was missing");
            return false;
        }
        acl.RemoveAce(foundIndex);
        return true;
    }

    internal static void VerifyDaclPreservation(RawSecurityDescriptor original, RawSecurityDescriptor updated, SecurityIdentifier addedSid, SecurityIdentifier removedSid)
    {
        if (original.ControlFlags != updated.ControlFlags) throw new Exception("Control flags were not preserved");
        RawAcl originalAcl = original.DiscretionaryAcl, updatedAcl = updated.DiscretionaryAcl;
        if (addedSid != null)
        {
            if (updatedAcl.Count != originalAcl.Count + 1) throw new Exception("Updated DACL count mismatch after addition");
            int origIdx = 0;
            for (int i = 0; i < updatedAcl.Count; i++)
            {
                CommonAce ace = updatedAcl[i] as CommonAce;
                if (ace != null && ace.SecurityIdentifier.Equals(addedSid))
                {
                    if (ace.AceQualifier != AceQualifier.AccessAllowed || ace.AceFlags != AceFlags.None || ace.AccessMask != NullDeviceAccessRights)
                        throw new Exception("Added ACE properties do not match expected grant");
                    continue;
                }
                if (origIdx >= originalAcl.Count) throw new Exception("Foreign ACE count mismatch");
                CommonAce origAce = originalAcl[origIdx++] as CommonAce;
                if (origAce == null || ace == null || origAce.AceQualifier != ace.AceQualifier || origAce.AceFlags != ace.AceFlags ||
                    origAce.AccessMask != ace.AccessMask || !origAce.SecurityIdentifier.Equals(ace.SecurityIdentifier))
                    throw new Exception("Foreign ACE was not preserved exactly");
            }
        }
        else if (removedSid != null)
        {
            if (updatedAcl.Count != originalAcl.Count - 1) throw new Exception("Updated DACL count mismatch after removal");
            int updIdx = 0;
            for (int i = 0; i < originalAcl.Count; i++)
            {
                CommonAce ace = originalAcl[i] as CommonAce;
                if (ace != null && ace.SecurityIdentifier.Equals(removedSid)) continue;
                if (updIdx >= updatedAcl.Count) throw new Exception("Foreign ACE count mismatch");
                CommonAce updAce = updatedAcl[updIdx++] as CommonAce;
                if (updAce == null || ace == null || updAce.AceQualifier != ace.AceQualifier || updAce.AceFlags != ace.AceFlags ||
                    updAce.AccessMask != ace.AccessMask || !updAce.SecurityIdentifier.Equals(ace.SecurityIdentifier))
                    throw new Exception("Foreign ACE was not preserved exactly");
            }
        }
    }

    internal static void ApplyKernelObjectGrant(IntPtr handle, SecurityIdentifier identity)
    {
        RawSecurityDescriptor before = ReadKernelDacl(handle);
        if (IsStockNullAccessSufficient(before, identity)) return;
        byte[] cloneBytes = new byte[before.BinaryLength];
        before.GetBinaryForm(cloneBytes, 0);
        RawSecurityDescriptor toModify = new RawSecurityDescriptor(cloneBytes, 0);
        ApplyNullDeviceAceToDescriptor(toModify, identity);
        WriteKernelDacl(handle, toModify);
        RawSecurityDescriptor verified = ReadKernelDacl(handle);
        if (!SameDacl(toModify, verified)) throw new Exception("Kernel object DACL update was not preserved exactly");
        VerifyDaclPreservation(before, verified, identity, null);
    }

    internal static bool RemoveKernelObjectGrant(IntPtr handle, SecurityIdentifier identity, bool requirePresent)
    {
        RawSecurityDescriptor before = ReadKernelDacl(handle);
        byte[] cloneBytes = new byte[before.BinaryLength];
        before.GetBinaryForm(cloneBytes, 0);
        RawSecurityDescriptor toModify = new RawSecurityDescriptor(cloneBytes, 0);
        bool removed = RemoveNullDeviceAceFromDescriptor(toModify, identity, requirePresent);
        if (!removed) return false;
        WriteKernelDacl(handle, toModify);
        RawSecurityDescriptor verified = ReadKernelDacl(handle);
        if (!SameDacl(toModify, verified)) throw new Exception("Kernel object DACL cleanup was not preserved exactly");
        VerifyDaclPreservation(before, verified, null, identity);
        return true;
    }

    static bool NullDeviceRequiresGrant(SecurityIdentifier identity)
    {
            IntPtr handle = CreateFile(NullDeviceKernelPath, StandardRightsRead, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (handle == InvalidHandle) Check(false, "Open Null device for inspection");
            try
            {
                RawSecurityDescriptor descriptor = ReadKernelDacl(handle);
                return !IsStockNullAccessSufficient(descriptor, identity);
            }
            finally { CloseHandle(handle); }
    }

    static void ApplyNullDeviceGrant(SecurityIdentifier identity)
    {
        using (NullDeviceGate.Acquire())
        {
            IntPtr handle = CreateFile(NullDeviceKernelPath, StandardRightsRead | StandardRightsWriteDac, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (handle == InvalidHandle)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "Open Null device for DACL modification (Win32 " + error + "): " + new Win32Exception(error).Message);
            }
            try
            {
                ApplyKernelObjectGrant(handle, identity);
            }
            finally { CloseHandle(handle); }
        }
    }

    static void ReconcileRecoveryNullDeviceGrant(SecurityIdentifier identity)
    {
        using (NullDeviceGate.Acquire())
        {
            IntPtr inspect = CreateFile(NullDeviceKernelPath, StandardRightsRead, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (inspect == InvalidHandle) Check(false, "Inspect pending Null device grant");
            try
            {
                RawSecurityDescriptor current = ReadKernelDacl(inspect);
                if (!RemoveNullDeviceAceFromDescriptor(current, identity, false)) return;
            }
            finally { CloseHandle(inspect); }
            IntPtr handle = CreateFile(NullDeviceKernelPath, StandardRightsRead | StandardRightsWriteDac, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (handle == InvalidHandle)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "Open Null device for recovery DACL cleanup (Win32 " + error + "): " + new Win32Exception(error).Message);
            }
            try
            {
                RemoveKernelObjectGrant(handle, identity, false);
            }
            finally { CloseHandle(handle); }
        }
    }

    // A lease written before the rename is settled under the names it recorded; the private lease file is the proof of ownership.
    static bool IsEarlierLease(Lease lease) { return !String.IsNullOrEmpty(lease.profile) && lease.profile.StartsWith("agy.test.", StringComparison.Ordinal); }

    static string LeasePrefix(Lease lease, string kind)
    {
        if (IsEarlierLease(lease)) return "agy-mcp-" + kind + "-";
        return kind == "copy" ? CopyPrefix(lease.cwd) : "black-gravity-" + kind + "-";
    }

    static string ExecutionJobName(Lease lease) { return "Global\\" + (IsEarlierLease(lease) ? "AGY.TEST" : "BLACK_GRAVITY.TEST") + ".JOB." + Guid.ParseExact(lease.nonce, "D").ToString("N"); }

    static IntPtr CreateExecutionJob(Lease lease, SecurityIdentifier user)
    {
        var acl = new RawAcl(RawAcl.AclRevision, 2);
        acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1f003f, user, false, null));
        acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1f003f, new SecurityIdentifier("S-1-5-18"), false, null));
        var descriptor = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected, user, null, null, acl);
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        IntPtr sd = Marshal.AllocHGlobal(bytes.Length), sa = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityAttributes)));
        try
        {
            Marshal.Copy(bytes, 0, sd, bytes.Length);
            Marshal.StructureToPtr(new SecurityAttributes { length = Marshal.SizeOf(typeof(SecurityAttributes)), descriptor = sd, inherit = 0 }, sa, false);
            IntPtr created = CreateJobObject(sa, ExecutionJobName(lease)); Check(created != IntPtr.Zero, "Create owned execution job");
            if (Marshal.GetLastWin32Error() == 183) { CloseHandle(created); throw new Exception("Execution job already exists"); }
            return created;
        }
        finally { Marshal.FreeHGlobal(sa); Marshal.FreeHGlobal(sd); }
    }

    internal static void WaitForEmptyJob(IntPtr job, int timeoutMilliseconds)
    {
        var timer = Stopwatch.StartNew(); IntPtr data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(JobAccounting)));
        try
        {
            for (;;)
            {
                Check(QueryInformationJobObject(job, 1, data, (uint)Marshal.SizeOf(typeof(JobAccounting)), IntPtr.Zero), "Verify owned job process count");
                if (((JobAccounting)Marshal.PtrToStructure(data, typeof(JobAccounting))).activeProcesses == 0) return;
                if (timer.ElapsedMilliseconds >= timeoutMilliseconds) throw new Exception("Owned job processes have not terminated");
                Thread.Sleep(10);
            }
        }
        finally { Marshal.FreeHGlobal(data); }
    }

    static void VerifyRecoveryJobEnded(Lease lease)
    {
        if (lease.version < 3 || lease.jobCreated != true) return;
        IntPtr job = OpenJobObject(4, false, ExecutionJobName(lease));
        if (job == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 2 || error == 1168) return;
            throw new Win32Exception(error, "Inspect interrupted execution job (Win32 " + error + ")");
        }
        try { WaitForEmptyJob(job, 5000); }
        finally { CloseHandle(job); }
    }

    static string Quote(string argument)
    {
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char character in argument)
        {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') result.Append('\\', slashes * 2 + 1);
            else result.Append('\\', slashes);
            result.Append(character); slashes = 0;
        }
        result.Append('\\', slashes * 2); return result.Append('"').ToString();
    }

    static long CurrentProcessStart()
    {
        FileTime created, exited, kernel, user;
        Check(GetProcessTimes(Process.GetCurrentProcess().Handle, out created, out exited, out kernel, out user), "Read controller start time");
        return FileTimeValue(created);
    }

    static void WriteLease(string path, Lease lease, bool initial, JavaScriptSerializer serializer)
    {
        byte[] data = new UTF8Encoding(false).GetBytes(serializer.Serialize(lease));
        if (initial)
        {
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { stream.Write(data, 0, data.Length); stream.Flush(true); }
            return;
        }
        string temporary = path + ".update." + Process.GetCurrentProcess().Id.ToString() + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { stream.Write(data, 0, data.Length); stream.Flush(true); }
        try { File.Replace(temporary, path, null); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    static void ValidateLease(Lease lease, string expectedFile, string stateDirectory)
    {
        Guid nonce;
        string canonicalState = CanonicalLocalPath(stateDirectory, "State directory");
        if (lease != null && IsInitLeaseVersion(lease.version))
        {
            Guid capNonce;
            bool validInitPhase = lease.phase == "init-workspace" || lease.phase == "prepared" || lease.phase == "cleanup-failed" ||
                (lease.version == 6 && lease.phase == "committed");
            if (!Guid.TryParseExact(lease.nonce, "D", out nonce) || Path.GetFileName(expectedFile) != nonce.ToString("N") + ".json" ||
                lease.controllerPid <= 0 || lease.controllerStarted <= 0 || lease.grants == null || lease.grants.Length != 1 ||
                !validInitPhase ||
                String.IsNullOrEmpty(lease.capabilityNonce) || !Guid.TryParseExact(lease.capabilityNonce, "D", out capNonce))
            {
                throw new Exception("Invalid Windows LPAC workspace initialization lease");
            }
            if ((lease.phase == "prepared" || lease.phase == "committed") && !IsLowerHex(lease.nativeDaclSha256, 64))
            {
                throw new Exception("Prepared Windows LPAC workspace initialization lease is missing DACL digest");
            }
            if ((lease.ownerPid != 0 || lease.ownerStarted != 0) && (lease.ownerPid <= 0 || lease.ownerStarted <= 0))
            {
                throw new Exception("Invalid workspace initialization owner in lease");
            }
            string fullCopy, rootKey, metadataPath;
            if (!TryGetCanonicalWorkspaceRootKey(lease.cwd, stateDirectory, out fullCopy, out rootKey, out metadataPath) ||
                lease.grants[0] == null || !String.Equals(lease.grants[0].path, fullCopy, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Invalid canonical workspace target in initialization lease");
            }
            SecurityIdentifier expectedRead = DeriveNamedCapabilitySid(WorkspaceCapabilityName(rootKey, capNonce, false));
            SecurityIdentifier expectedModify = DeriveNamedCapabilitySid(WorkspaceCapabilityName(rootKey, capNonce, true));
            if (String.IsNullOrEmpty(lease.readCapabilitySid) || String.IsNullOrEmpty(lease.modifyCapabilitySid) ||
                !expectedRead.Equals(new SecurityIdentifier(lease.readCapabilitySid)) ||
                !expectedModify.Equals(new SecurityIdentifier(lease.modifyCapabilitySid)))
            {
                throw new Exception("Invalid workspace capability SID in initialization lease");
            }
            if (lease.version == 4 && lease.mcpCustody != null)
            {
                throw new Exception("Version 4 workspace initialization lease cannot declare MCP custody");
            }
            if (lease.version == 6)
            {
                if (lease.mcpCustody == null) throw new Exception("Version 6 workspace initialization lease requires MCP custody");
                ValidateMcpCustodyLease(lease.mcpCustody, fullCopy, canonicalState, nonce);
            }
            return;
        }
        if (lease == null || (lease.version != 1 && lease.version != 2 && lease.version != 3 && lease.version != 5) || !Guid.TryParseExact(lease.nonce, "D", out nonce) || String.IsNullOrEmpty(lease.profile) ||
            (!String.Equals(lease.profile, "black-gravity.test." + nonce.ToString("N"), StringComparison.Ordinal) && !(lease.version <= 3 && String.Equals(lease.profile, "agy.test." + nonce.ToString("N"), StringComparison.Ordinal))) || Path.GetFileName(expectedFile) != nonce.ToString("N") + ".json" ||
            lease.controllerPid <= 0 || lease.controllerStarted <= 0 || lease.grants == null || (lease.phase != "creating" && lease.phase != "active" && lease.phase != "cleanup-failed")) throw new Exception("Invalid Windows LPAC lease");
        if (lease.phase != "creating" && String.IsNullOrEmpty(lease.sid)) throw new Exception("Lease has no profile identity");
        string canonicalCopy, canonicalRootKey, canonicalMeta;
        bool isCanonicalCopy = IsRunLeaseWithJobVersion(lease.version) && !IsEarlierLease(lease) &&
            TryGetCanonicalWorkspaceRootKey(lease.cwd, stateDirectory, out canonicalCopy, out canonicalRootKey, out canonicalMeta);
        if (!isCanonicalCopy)
        {
            OwnedTemporaryPath(lease.cwd, LeasePrefix(lease, "copy"));
        }
        OwnedTemporaryPath(lease.runtime, LeasePrefix(lease, "runtime")); OwnedTemporaryPath(lease.scratch, LeasePrefix(lease, "scratch"));
        if (lease.version < 3 && (lease.nullDeviceGrant || lease.jobCreated == true || lease.mcpCustody != null)) throw new Exception("Legacy lease cannot declare Null device grant, named job, or MCP custody");
        if (lease.version == 3 && lease.mcpCustody != null) throw new Exception("Version 3 lease cannot declare MCP custody");
        if (lease.version == 5 && lease.mcpCustody == null) throw new Exception("Version 5 lease requires MCP custody");
        if (lease.version == 2 || IsRunLeaseWithJobVersion(lease.version)) ValidateLeaseAliases(lease, nonce);
        if (IsRunLeaseWithJobVersion(lease.version) && !lease.jobCreated.HasValue) throw new Exception("Lease has no job creation state");
        if ((lease.nullDeviceGrant || lease.jobCreated == true) && (lease.phase == "creating" || String.IsNullOrEmpty(lease.sid))) throw new Exception("Lease has no verified execution identity");
        if (lease.version == 5) ValidateMcpCustodyLease(lease.mcpCustody, lease.cwd, canonicalState, nonce);
    }

    static void ValidateLeaseAliases(Lease lease, Guid nonce)
    {
        Luid logon; if (!TryParseLogon(lease.logon, out logon) || lease.aliases == null || lease.aliases.Length != 3) throw new Exception("Invalid Windows LPAC alias lease");
        string[] kinds = new string[] { "copy", "runtime", "scratch" }, roots = new string[] { lease.cwd, lease.runtime, lease.scratch }; var drives = new HashSet<char>();
        for (int index = 0; index < lease.aliases.Length; index++)
        {
            AliasPlan alias = lease.aliases[index];
            if (alias == null || !String.Equals(alias.kind, kinds[index], StringComparison.Ordinal) || !String.Equals(alias.physicalRoot, roots[index], StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(alias.customName, (IsEarlierLease(lease) ? "AGY.TEST." : "BLACK_GRAVITY.TEST.") + nonce.ToString("D").ToUpperInvariant() + "." + kinds[index].ToUpperInvariant(), StringComparison.Ordinal) ||
                String.IsNullOrEmpty(alias.drive) || alias.drive.Length != 2 || alias.drive[0] < 'D' || alias.drive[0] > 'Z' || alias.drive[1] != ':' || !drives.Add(alias.drive[0]) || (index != 0 && alias.drive[0] >= lease.aliases[index - 1].drive[0]) || !String.Equals(alias.aliasRoot, alias.drive + "\\", StringComparison.Ordinal) ||
                !String.Equals(alias.customTarget, RawDosTarget(roots[index]), StringComparison.Ordinal) || !String.Equals(alias.driveTarget, RawDosTarget(alias.customName), StringComparison.Ordinal)) throw new Exception("Invalid Windows LPAC alias plan");
        }
    }

    static long ActiveProcessStart(int pid, string description)
    {
        if (pid <= 0) throw new Exception("Invalid " + description + " PID");
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation | Synchronize, false, (uint)pid);
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open " + description);
        }
        try
        {
            FileTime created, exited, kernel, user;
            Check(GetProcessTimes(process, out created, out exited, out kernel, out user), "Read " + description + " start time");
            uint state = WaitForSingleObject(process, 0);
            if (state == WaitTimeout) return FileTimeValue(created);
            if (state == WaitObject0) throw new Exception(description + " has already exited");
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Verify " + description + " state");
        }
        finally { CloseHandle(process); }
    }

    static bool ProcessIsActive(int pid, long started, string description)
    {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation | Synchronize, false, (uint)pid);
        if (process == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 87 || error == 1168) return false;
            throw new Win32Exception(error, "Cannot verify " + description);
        }
        try
        {
            FileTime created, exited, kernel, user;
            Check(GetProcessTimes(process, out created, out exited, out kernel, out user), "Verify " + description + " start time");
            uint state = WaitForSingleObject(process, 0);
            if (state == WaitTimeout) return FileTimeValue(created) == started;
            if (state == WaitObject0) return false;
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Verify " + description + " state");
        }
        finally { CloseHandle(process); }
    }

    static bool ControllerIsActive(Lease lease)
    {
        return ProcessIsActive(lease.controllerPid, lease.controllerStarted, "lease controller");
    }

    static bool HasActivePreparedOwnerHold(Lease lease, string leaseFile)
    {
        if (lease == null || !IsInitLeaseVersion(lease.version) || (lease.phase != "prepared" && lease.phase != "committed")) return false;
        if (lease.ownerPid <= 0 || lease.ownerStarted <= 0) return false;
        string holdFile = LeaseHoldFile(leaseFile);
        uint attrs = GetFileAttributes(holdFile);
        if (attrs == InvalidFileAttributes)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 2 || error == 3) return false;
            throw new Win32Exception(error, "Cannot inspect workspace initialization hold");
        }
        if ((attrs & (uint)FileAttributes.ReparsePoint) != 0 || (attrs & (uint)FileAttributes.Directory) != 0)
        {
            throw new Exception("Workspace initialization hold is linked or invalid");
        }
        if (ProcessIsActive(lease.ownerPid, lease.ownerStarted, "workspace initialization owner"))
        {
            return true;
        }
        DeleteLeaseHoldIfPresent(leaseFile);
        return false;
    }

    static bool TryReadValidatedLease(string file, string stateDirectory, JavaScriptSerializer serializer, out Lease lease)
    {
        lease = null;
        uint attrs = GetFileAttributes(file);
        if (attrs == InvalidFileAttributes)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 2 || error == 3) return false;
            throw new Win32Exception(error, "Inspect lease file");
        }
        if ((attrs & (uint)FileAttributes.ReparsePoint) != 0) throw new Exception("Lease file is linked");
        string content;
        try { content = File.ReadAllText(file, Encoding.UTF8); }
        catch (FileNotFoundException) { return false; }
        lease = serializer.Deserialize<Lease>(content);
        ValidateLease(lease, file, stateDirectory);
        return true;
    }

    static SecurityIdentifier LeaseIdentity(Lease lease)
    {
        if (String.IsNullOrEmpty(lease.sid))
        {
            if (lease.phase == "creating") return null;
            throw new Exception("Lease has no profile identity");
        }
        var identity = new SecurityIdentifier(lease.sid);
        IntPtr derived; int result = DeriveAppContainerSidFromAppContainerName(lease.profile, out derived);
        if (result >= 0 && derived != IntPtr.Zero)
        {
            try { if (!identity.Equals(new SecurityIdentifier(derived))) throw new Exception("Lease profile SID does not match its profile name"); }
            finally { FreeSid(derived); }
        }
        else if (!IsNotFoundHresult(result)) CheckHr(result, "Verify lease profile SID");
        return identity;
    }

    static bool IsMissingOwnedTemporaryGrant(Lease lease, Grant grant, string stateDirectory)
    {
        if (grant == null || !grant.directory) return false;
        string directory = null, prefix = null;
        if (String.Equals(grant.path, lease.cwd, StringComparison.OrdinalIgnoreCase))
        {
            string fullCopy, rootKey, metadataPath;
            if (lease.version >= 3 && !IsEarlierLease(lease) && TryGetCanonicalWorkspaceRootKey(lease.cwd, stateDirectory, out fullCopy, out rootKey, out metadataPath))
            {
                if (GetFileAttributes(fullCopy) != InvalidFileAttributes) return false;
                int canonicalError = Marshal.GetLastWin32Error();
                return canonicalError == 2 || canonicalError == 3;
            }
            directory = lease.cwd; prefix = LeasePrefix(lease, "copy");
        }
        else if (String.Equals(grant.path, lease.runtime, StringComparison.OrdinalIgnoreCase)) { directory = lease.runtime; prefix = LeasePrefix(lease, "runtime"); }
        else if (String.Equals(grant.path, lease.scratch, StringComparison.OrdinalIgnoreCase)) { directory = lease.scratch; prefix = LeasePrefix(lease, "scratch"); }
        else return false;
        directory = OwnedTemporaryPath(directory, prefix);
        if (GetFileAttributes(directory) != InvalidFileAttributes) return false;
        int error = Marshal.GetLastWin32Error();
        return error == 2 || error == 3;
    }

    static void DeleteProfile(string profile)
    {
        int result = DeleteAppContainerProfile(profile);
        if (result < 0 && !IsNotFoundHresult(result)) CheckHr(result, "Delete AppContainer profile");
    }

    static void Recover(string stateDirectory, Dictionary<string, object> result, JavaScriptSerializer serializer)
    {
        string canonicalState = CanonicalLocalPath(stateDirectory, "State directory");
        string directory = StateLeaseDirectory(stateDirectory); var failures = new List<string>(); int recovered = 0, active = 0;
        foreach (string file in Directory.GetFiles(directory, "*.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                Lease lease;
                if (!TryReadValidatedLease(file, stateDirectory, serializer, out lease)) continue;
                if (ControllerIsActive(lease)) { active++; continue; }
                if (!TryReadValidatedLease(file, stateDirectory, serializer, out lease)) continue;
                if (ControllerIsActive(lease)) { active++; continue; }
                if (IsInitLeaseVersion(lease.version))
                {
                    if (lease.phase == "committed")
                    {
                        if (HasActivePreparedOwnerHold(lease, file)) { active++; continue; }
                        if (!LeaseFileExists(file)) continue;
                        ValidateCommittedLeaseMetadataFile(lease, stateDirectory, canonicalState, serializer);
                        if (lease.mcpCustody != null)
                        {
                            ControllerIdentity initController = CurrentControllerIdentity();
                            string qReason;
                            RestoreOrQuarantineMcpConfigCustody(lease, canonicalState, initController.user, null, serializer, out qReason);
                        }
                        File.Delete(file);
                        DeleteLeaseHoldIfPresent(file);
                        recovered++;
                        continue;
                    }
                    if (lease.phase == "prepared")
                    {
                        if (HasActivePreparedOwnerHold(lease, file)) { active++; continue; }
                        if (!LeaseFileExists(file)) continue;
                        string commitReason;
                        WorkspaceInitCommitState commitState = InspectWorkspaceInitCommit(lease, stateDirectory, serializer, out commitReason);
                        if (commitState == WorkspaceInitCommitState.Committed)
                        {
                            if (lease.mcpCustody != null)
                            {
                                lease.phase = "committed";
                                WriteLease(file, lease, false, serializer);
                                ControllerIdentity initController = CurrentControllerIdentity();
                                string qReason;
                                RestoreOrQuarantineMcpConfigCustody(lease, canonicalState, initController.user, null, serializer, out qReason);
                            }
                            File.Delete(file);
                            DeleteLeaseHoldIfPresent(file);
                            recovered++;
                            continue;
                        }
                        if (commitState == WorkspaceInitCommitState.Inconclusive)
                        {
                            if (!LeaseFileExists(file)) continue;
                            throw new Exception("Prepared workspace initialization commit check was inconclusive; skipping revocation" + (String.IsNullOrEmpty(commitReason) ? "" : ": " + commitReason));
                        }
                    }
                    var initFailures = new List<string>();
                    if (!IsMissingOwnedTemporaryGrant(lease, lease.grants[0], stateDirectory))
                    {
                        try { Access(new PinnedTarget { grant = lease.grants[0] }, new SecurityIdentifier(lease.modifyCapabilitySid), false); }
                        catch (Exception error) { initFailures.Add("Modify capability ACL: " + error.Message); }
                        try { Access(new PinnedTarget { grant = lease.grants[0] }, new SecurityIdentifier(lease.readCapabilitySid), false); }
                        catch (Exception error) { initFailures.Add("Read capability ACL: " + error.Message); }
                    }
                    if (initFailures.Count == 0 && lease.mcpCustody != null)
                    {
                        try
                        {
                            ControllerIdentity initController = CurrentControllerIdentity();
                            string qReason;
                            RestoreOrQuarantineMcpConfigCustody(lease, canonicalState, initController.user, null, serializer, out qReason);
                        }
                        catch (Exception error) { initFailures.Add("MCP config custody: " + error.Message); }
                    }
                    if (initFailures.Count != 0)
                    {
                        lease.phase = "cleanup-failed";
                        try { WriteLease(file, lease, false, serializer); } catch (Exception update) { initFailures.Add("Lease: " + update.Message); }
                        throw new Exception(String.Join("; ", initFailures.ToArray()));
                    }
                    File.Delete(file);
                    DeleteLeaseHoldIfPresent(file);
                    recovered++;
                    continue;
                }
                SecurityIdentifier identity = LeaseIdentity(lease); VerifyRecoveryJobEnded(lease); var pins = new List<PinnedTarget>(); var cleanupFailures = new List<string>();
                ControllerIdentity recoveryController = null;
                try
                {
                    if (lease.version == 2 || IsRunLeaseWithJobVersion(lease.version))
                    {
                        try
                        {
                            recoveryController = CurrentControllerIdentity();
                            if (String.Equals(recoveryController.logon, lease.logon, StringComparison.Ordinal))
                            {
                                AcquireRecoveryAliasGates(lease.aliases, recoveryController, lease.logon);
                                try { RemoveAliases(lease.aliases); }
                                finally { ReleaseAliasGates(lease.aliases); }
                            }
                            else if (LogonSessionExists(lease.logon)) throw new Exception("Lease logon session remains active");
                        }
                        catch (Exception error) { cleanupFailures.Add("DOS aliases: " + error.Message); }
                    }
                    if (IsRunLeaseWithJobVersion(lease.version) && lease.nullDeviceGrant && identity != null)
                    {
                        try { ReconcileRecoveryNullDeviceGrant(identity); }
                        catch (Exception error) { cleanupFailures.Add("Null device: " + error.Message); }
                    }
                    if (identity != null)
                    {
                        for (int index = lease.grants.Length - 1; index >= 0; index--)
                        {
                            if (IsMissingOwnedTemporaryGrant(lease, lease.grants[index], stateDirectory)) continue;
                            try { Access(new PinnedTarget { grant = lease.grants[index] }, identity, false); }
                            catch (Exception error) { cleanupFailures.Add("ACL " + index.ToString() + ": " + error.Message); }
                        }
                    }
                    try { DeleteProfile(lease.profile); } catch (Exception error) { cleanupFailures.Add("Profile: " + error.Message); }
                    if (cleanupFailures.Count == 0 && lease.mcpCustody != null)
                    {
                        try
                        {
                            if (recoveryController == null) recoveryController = CurrentControllerIdentity();
                            string qReason;
                            RestoreOrQuarantineMcpConfigCustody(lease, canonicalState, recoveryController.user, null, serializer, out qReason);
                        }
                        catch (Exception error) { cleanupFailures.Add("MCP config custody: " + error.Message); }
                    }
                }
                finally { for (int index = pins.Count - 1; index >= 0; index--) pins[index].Dispose(); }
                if (cleanupFailures.Count != 0)
                {
                    if (!String.IsNullOrEmpty(lease.sid)) lease.phase = "cleanup-failed";
                    try { WriteLease(file, lease, false, serializer); } catch (Exception update) { cleanupFailures.Add("Lease: " + update.Message); }
                    throw new Exception(String.Join("; ", cleanupFailures.ToArray()));
                }
                File.Delete(file); recovered++;
            }
            catch (Exception error) { failures.Add(Path.GetFileName(file) + ": " + error.Message); }
        }
        result["recovered"] = recovered; result["active"] = active;
        if (failures.Count != 0) result["error"] = "Windows LPAC recovery failed: " + String.Join("; ", failures.ToArray());
    }

    static IntPtr DeriveCapability(string name, List<IntPtr> allocations)
    {
        IntPtr groups, caps; uint groupCount, capabilityCount;
        Check(DeriveCapabilitySidsFromName(name, out groups, out groupCount, out caps, out capabilityCount), "Derive " + name + " capability");
        try
        {
            if (capabilityCount != 1) throw new Exception("Unexpected " + name + " capability count");
            IntPtr sid = Marshal.ReadIntPtr(caps); allocations.Add(sid); return sid;
        }
        finally
        {
            for (int index = 0; index < (int)groupCount; index++) LocalFree(Marshal.ReadIntPtr(groups, index * IntPtr.Size));
            if (groups != IntPtr.Zero) LocalFree(groups);
            if (caps != IntPtr.Zero) LocalFree(caps);
        }
    }

    static void AddGrant(List<Grant> grants, string path, string rights)
    {
        if (String.IsNullOrEmpty(path)) throw new Exception("Missing owned permission target");
        foreach (Grant existing in grants) if (String.Equals(existing.path, path, StringComparison.OrdinalIgnoreCase)) { if (rights == "modify") existing.rights = "modify"; return; }
        grants.Add(new Grant { path = path, rights = rights });
    }

    static bool IsBridgeOwnedTemporaryPath(string value)
    {
        foreach (string part in value.Split(new char[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries))
        {
            // Directories of the previous name stay protected while a copy created before the rename survives.
            foreach (string owner in new string[] { "black-gravity-", "agy-mcp-" })
            {
                if (!part.StartsWith(owner, StringComparison.OrdinalIgnoreCase)) continue;
                string kind = part.Substring(owner.Length);
                if (kind.StartsWith("copy-", StringComparison.OrdinalIgnoreCase) || kind.StartsWith("baseline-", StringComparison.OrdinalIgnoreCase) ||
                    kind.StartsWith("runtime-", StringComparison.OrdinalIgnoreCase) || kind.StartsWith("controller-", StringComparison.OrdinalIgnoreCase) ||
                    kind.StartsWith("scratch-", StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        return false;
    }

    const int MaxDiagnosticCharacters = 64000;
    internal const string OversizedDiagnosticMessage = "Execution diagnostic omitted: exceeded 64000 characters [truncated]";

    internal static string CombineDiagnostic(string primary, string secondary)
    {
        long length = (primary == null ? 0 : primary.Length) + (long)(secondary == null ? 0 : secondary.Length);
        if (!String.IsNullOrEmpty(primary) && !String.IsNullOrEmpty(secondary)) length += 2;
        if (length > MaxDiagnosticCharacters) return OversizedDiagnosticMessage;
        if (String.IsNullOrEmpty(primary)) return secondary ?? "";
        if (String.IsNullOrEmpty(secondary)) return primary;
        return primary + "; " + secondary;
    }

    static int Main(string[] arguments)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        var serializer = new JavaScriptSerializer { MaxJsonLength = 2 * 1024 * 1024 };
        var result = new Dictionary<string, object>();
        string profile = null, leaseFile = null, cwd = null, runtime = null, scratch = null, canonicalState = null;
        SecurityIdentifier identity = null; Lease lease = null;
        ControllerIdentity controller = null; AliasPlan[] aliases = null;
        McpCustodyHold mcpHold = null;
        IntPtr sid = IntPtr.Zero, job = IntPtr.Zero, attributes = IntPtr.Zero, capabilityData = IntPtr.Zero, lpacData = IntPtr.Zero, handleData = IntPtr.Zero, jobData = IntPtr.Zero, envData = IntPtr.Zero, capabilityList = IntPtr.Zero;
        IntPtr read = IntPtr.Zero, write = IntPtr.Zero, inputRead = IntPtr.Zero, inputWrite = IntPtr.Zero;
        ProcessInfo child = new ProcessInfo(); bool attributesInitialized = false, profileCreated = false, nullDeviceGranted = false, leaseWritten = false;
        var pins = new List<PinnedTarget>(); var applied = new List<PinnedTarget>();
        var capabilitySids = new List<IntPtr>();
        var output = new StringBuilder(); bool truncated = false; Thread reader = null; object jobGate = new object(); int cancellation = 0;
        try
        {
            if (arguments.Length != 1) throw new Exception("One controller request file is required");
            var request = serializer.Deserialize<Request>(File.ReadAllText(arguments[0], Encoding.UTF8));
            if (request == null || String.IsNullOrEmpty(request.action)) throw new Exception("Invalid controller request");
            if (request.action == "recover")
            {
                Recover(request.stateDirectory, result, serializer); result["output"] = ""; result["truncated"] = false;
                Console.WriteLine(serializer.Serialize(result)); return result.ContainsKey("error") ? 1 : 0;
            }
            if (request.action == "init-workspace")
            {
                InitWorkspace(request, result, serializer); result["output"] = ""; result["truncated"] = false;
                Console.WriteLine(serializer.Serialize(result)); return result.ContainsKey("error") ? 1 : 0;
            }
            if (request.action == "commit-workspace-lease")
            {
                CommitWorkspaceLease(request, result, serializer); result["output"] = ""; result["truncated"] = false;
                Console.WriteLine(serializer.Serialize(result)); return result.ContainsKey("error") ? 1 : 0;
            }
            if (request.action != "write" && request.action != "read-only") throw new Exception("Invalid controller action");
            Guid nonce; if (!Guid.TryParseExact(request.nonce, "D", out nonce)) throw new Exception("Invalid nonce");
            if (!String.Equals(request.profile, "black-gravity.test." + nonce.ToString("N"), StringComparison.Ordinal)) throw new Exception("Invalid deterministic profile name");
            result["nonce"] = request.nonce;
            if (request.timeoutSeconds < 1 || request.timeoutSeconds > 86400 || request.maxFiles < 1 || request.maxFiles > 1000000 || request.maxOutputChars < 256 || request.maxOutputChars > 64000 || request.args == null || request.environment == null || request.grants == null) throw new Exception("Invalid request");
            if (request.args.Length > 50) throw new Exception("Too many command arguments");
            foreach (string argument in request.args) if (argument == null || argument.Length > 4000 || argument.IndexOf('\0') >= 0) throw new Exception("Invalid command argument");
            ValidateMcpCustodyRequest(request.mcpCustody);
            string state = StateLeaseDirectory(request.stateDirectory);
            canonicalState = Path.GetFullPath(request.stateDirectory).TrimEnd(Path.DirectorySeparatorChar);
            CanonicalWorkspaceInfo canonicalWorkspace = null;
            string canonicalCopyPath, canonicalRootKey, canonicalMetaPath;
            if (TryGetCanonicalWorkspaceRootKey(request.cwd, canonicalState, out canonicalCopyPath, out canonicalRootKey, out canonicalMetaPath))
            {
                canonicalWorkspace = ValidateCanonicalWorkspaceCopy(request.cwd, canonicalState, serializer, true);
                cwd = canonicalWorkspace.copyPath;
            }
            else
            {
                cwd = OwnedDirectory(request.cwd, CopyPrefix(request.cwd));
            }
            runtime = OwnedDirectory(request.runtime, "black-gravity-runtime-"); scratch = OwnedDirectory(request.scratch, "black-gravity-scratch-");
            string executable = Path.GetFullPath(request.executable);
            if (!executable.StartsWith(runtime + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !File.Exists(executable) || (File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0) throw new Exception("Executable must be staged inside the runtime");
            var requestedGrants = new List<Grant>();
            AddGrant(requestedGrants, cwd, request.action == "read-only" ? "read" : "modify");
            AddGrant(requestedGrants, runtime, "read"); AddGrant(requestedGrants, scratch, "modify");
            foreach (Grant grant in request.grants)
            {
                if (grant == null) throw new Exception("Invalid permission grant");
                RequireLocalAbsolutePath(grant.path, "External permission grant");
                if (IsBridgeOwnedTemporaryPath(grant.path) || OverlapsPath(grant.path, canonicalState)) throw new Exception("External permission grant targets bridge-owned storage");
                AddGrant(requestedGrants, grant.path, grant.rights);
            }
            if (requestedGrants.Count > 23) throw new Exception("Too many permission grants");
            foreach (Grant grant in requestedGrants) pins.Add(PinGrant(grant, request.maxFiles));
            profile = request.profile; leaseFile = Path.Combine(state, nonce.ToString("N") + ".json");
            controller = CurrentControllerIdentity(); aliases = CreateAliasPlan(nonce, controller, new PinnedTarget[] { pins[0], pins[1], pins[2] });
            result["pathMappings"] = PathMappings(aliases);
            lease = new Lease { version = request.mcpCustody != null ? 5 : 3, nonce = request.nonce, profile = profile, phase = "creating", controllerPid = Process.GetCurrentProcess().Id, controllerStarted = CurrentProcessStart(), cwd = cwd, runtime = runtime, scratch = scratch, grants = new Grant[0], logon = controller.logon, aliases = aliases, nullDeviceGrant = false, jobCreated = false };
            if (request.mcpCustody != null)
            {
                mcpHold = AcquireMcpConfigCustody(request.mcpCustody, cwd, canonicalState, nonce, controller, lease, leaseFile, ref leaseWritten, serializer);
            }
            if (canonicalWorkspace != null)
            {
                if (pins[0].grant.volume != (uint)canonicalWorkspace.meta.windowsLpac.volume.Value ||
                    pins[0].grant.fileIndexHigh != (uint)canonicalWorkspace.meta.windowsLpac.fileIndexHigh.Value ||
                    pins[0].grant.fileIndexLow != (uint)canonicalWorkspace.meta.windowsLpac.fileIndexLow.Value)
                {
                    throw new Exception("Canonical workspace folder identity changed since LPAC baseline was pinned");
                }
                ValidateCanonicalWorkspaceDacl(
                    pins[0],
                    canonicalWorkspace.readSid,
                    canonicalWorkspace.modifySid,
                    canonicalWorkspace.meta.windowsLpac.nativeDaclSha256,
                    true,
                    request.maxFiles);
                result["workspaceLpacValidated"] = true;
            }
            int ephemeralGrantStart = canonicalWorkspace != null ? 1 : 0;
            if (!leaseWritten)
            {
                WriteLease(leaseFile, lease, true, serializer);
                leaseWritten = true;
            }
            CheckHr(CreateAppContainerProfile(profile, profile, "Isolated test process", IntPtr.Zero, 0, out sid), "CreateAppContainerProfile");
            profileCreated = true; identity = new SecurityIdentifier(sid);
            lease.sid = identity.Value; WriteLease(leaseFile, lease, false, serializer);
            Directory.CreateDirectory(Path.Combine(scratch, "Packages", profile, "AC", "Temp"));
            Directory.CreateDirectory(Path.Combine(scratch, "Packages", profile, "AC", "Local"));
            bool needNullGrant = request.environment.ContainsKey("GIT_EXEC_PATH") && NullDeviceRequiresGrant(identity);
            var recorded = new List<Grant>(); for (int index = ephemeralGrantStart; index < pins.Count; index++) recorded.Add(pins[index].grant);
            lease.sid = identity.Value; lease.grants = recorded.ToArray(); lease.nullDeviceGrant = needNullGrant; lease.phase = "active"; WriteLease(leaseFile, lease, false, serializer);
            if (needNullGrant)
            {
                nullDeviceGranted = true;
                ApplyNullDeviceGrant(identity);
            }
            for (int index = ephemeralGrantStart; index < pins.Count; index++) { applied.Add(pins[index]); Access(pins[index], identity, true); }
            ApplyAliases(aliases); result["pathMappings"] = PathMappings(aliases);

            var inheritable = new SecurityAttributes { length = Marshal.SizeOf(typeof(SecurityAttributes)), inherit = 1 };
            Check(CreatePipe(out read, out write, ref inheritable, 0), "Create output pipe"); Check(SetHandleInformation(read, 1, 0), "Protect output reader");
            Check(CreatePipe(out inputRead, out inputWrite, ref inheritable, 0), "Create input pipe"); CloseHandle(inputWrite); inputWrite = IntPtr.Zero;
            job = CreateExecutionJob(lease, controller.user);
            lease.jobCreated = true; WriteLease(leaseFile, lease, false, serializer);
            var limits = new ExtendedLimits(); limits.basic.flags = JobObjectLimitKillOnJobClose | (request.childProcesses ? 0u : JobObjectLimitActiveProcess); limits.basic.activeProcesses = request.childProcesses ? 0u : 1u; IntPtr limitData = Marshal.AllocHGlobal(Marshal.SizeOf(limits));
            try { Marshal.StructureToPtr(limits, limitData, false); Check(SetInformationJobObject(job, (int)JobObjectExtendedLimitInformation, limitData, (uint)Marshal.SizeOf(limits)), "Require job cleanup"); Marshal.DestroyStructure(limitData, typeof(ExtendedLimits)); Check(QueryInformationJobObject(job, (int)JobObjectExtendedLimitInformation, limitData, (uint)Marshal.SizeOf(limits), IntPtr.Zero), "Verify job limits"); var observed = (ExtendedLimits)Marshal.PtrToStructure(limitData, typeof(ExtendedLimits)); if ((observed.basic.flags & JobObjectLimitKillOnJobClose) == 0 || (observed.basic.flags & (JobObjectLimitBreakawayOk | JobObjectLimitSilentBreakawayOk)) != 0 || (!request.childProcesses && ((observed.basic.flags & JobObjectLimitActiveProcess) == 0 || observed.basic.activeProcesses != 1))) throw new Exception("Job limits were not applied"); }
            finally { Marshal.FreeHGlobal(limitData); }
            DeriveCapability("registryRead", capabilitySids);
            if (canonicalWorkspace != null)
            {
                bool isModify = request.action == "write";
                IntPtr workspaceCap = DeriveCapability(WorkspaceCapabilityName(canonicalWorkspace.rootKey, canonicalWorkspace.capabilityNonce, isModify), capabilitySids);
                SecurityIdentifier expectedCap = isModify ? canonicalWorkspace.modifySid : canonicalWorkspace.readSid;
                if (!expectedCap.Equals(new SecurityIdentifier(workspaceCap))) throw new Exception("Derived workspace capability SID mismatch");
            }
            if (request.network) { DeriveCapability("internetClient", capabilitySids); DeriveCapability("privateNetworkClientServer", capabilitySids); }
                int sidAndAttributesSize = Marshal.SizeOf(typeof(SidAndAttributes)); capabilityList = Marshal.AllocHGlobal(sidAndAttributesSize * capabilitySids.Count);
                for (int index = 0; index < capabilitySids.Count; index++) Marshal.StructureToPtr(new SidAndAttributes { sid = capabilitySids[index], attributes = 4 }, IntPtr.Add(capabilityList, index * sidAndAttributesSize), false);
                var caps = new SecurityCapabilities { sid = sid, capabilities = capabilityList, count = (uint)capabilitySids.Count };
                capabilityData = Marshal.AllocHGlobal(Marshal.SizeOf(caps)); Marshal.StructureToPtr(caps, capabilityData, false);
                int attributeCount = 4; UIntPtr size = UIntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, attributeCount, 0, ref size);
                attributes = Marshal.AllocHGlobal(checked((int)size.ToUInt64())); Check(InitializeProcThreadAttributeList(attributes, attributeCount, 0, ref size), "Initialize attributes"); attributesInitialized = true;
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeSecurityCapabilities), capabilityData, new UIntPtr((uint)Marshal.SizeOf(caps)), IntPtr.Zero, IntPtr.Zero), "Set AppContainer");
                lpacData = Marshal.AllocHGlobal(4); Marshal.WriteInt32(lpacData, (int)AllApplicationPackagesPolicyLpac);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeAllApplicationPackagesPolicy), lpacData, new UIntPtr(4), IntPtr.Zero, IntPtr.Zero), "Require LPAC");
                handleData = Marshal.AllocHGlobal(IntPtr.Size * 2); Marshal.WriteIntPtr(handleData, write); Marshal.WriteIntPtr(handleData, IntPtr.Size, inputRead);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeHandleList), handleData, new UIntPtr((uint)(IntPtr.Size * 2)), IntPtr.Zero, IntPtr.Zero), "Restrict inherited handles");
                jobData = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobData, job);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeJobList), jobData, new UIntPtr((uint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "Assign job at process creation");
            var startup = new StartupInfoEx(); startup.startup.cb = Marshal.SizeOf(startup); startup.startup.flags = 0x100; startup.startup.input = inputRead; startup.startup.output = write; startup.startup.error = write; startup.attributes = attributes;
            string aliasExecutable = ProjectOwnedPath(executable, aliases), aliasCwd = ProjectOwnedPath(cwd, aliases); if (String.Equals(aliasExecutable, executable, StringComparison.OrdinalIgnoreCase) || String.Equals(aliasCwd, cwd, StringComparison.OrdinalIgnoreCase)) throw new Exception("Owned paths were not projected to DOS aliases");
            var command = new StringBuilder(Quote(aliasExecutable)); foreach (string argument in ProjectArguments(request.args, aliases)) command.Append(' ').Append(Quote(argument));
            Dictionary<string, string> projectedEnvironment = ProjectEnvironment(request, aliases); var environment = new StringBuilder(); var keys = new List<string>(projectedEnvironment.Keys); keys.Sort(StringComparer.OrdinalIgnoreCase);
            foreach (string key in keys) { string value = projectedEnvironment[key]; if (String.IsNullOrEmpty(key) || value == null || key.IndexOfAny(new char[] { '=', '\0' }) >= 0 || value.IndexOf('\0') >= 0) throw new Exception("Invalid environment"); environment.Append(key).Append('=').Append(value).Append('\0'); }
            environment.Append('\0'); envData = Marshal.StringToHGlobalUni(environment.ToString());
            Check(CreateProcess(aliasExecutable, command, IntPtr.Zero, IntPtr.Zero, true, 0x80000 | 0x400 | 0x4 | 0x8000000, envData, aliasCwd, ref startup, out child), "Create isolated process");
            foreach (IntPtr capability in capabilitySids) if (capability != IntPtr.Zero) LocalFree(capability);
            capabilitySids.Clear();
            bool inJob; Check(IsProcessInJob(child.process, job, out inJob) && inJob, "Verify isolated job");
            IntPtr token; Check(OpenProcessToken(child.process, 8, out token), "Inspect child token");
            try
            {
                IntPtr info = Marshal.AllocHGlobal(IntPtr.Size); uint returned;
                try
                {
                    Check(GetTokenInformation(token, 29, info, (uint)IntPtr.Size, out returned), "Verify AppContainer token"); if (Marshal.ReadInt32(info) != 1) throw new Exception("AppContainer token missing");
                    GetTokenInformation(token, 31, IntPtr.Zero, 0, out returned); if (returned < IntPtr.Size || returned > 65536) throw new Exception("Invalid package identity size"); IntPtr packageInfo = Marshal.AllocHGlobal(checked((int)returned));
                    try { Check(GetTokenInformation(token, 31, packageInfo, returned, out returned), "Verify package identity"); if (!identity.Equals(new SecurityIdentifier(Marshal.ReadIntPtr(packageInfo)))) throw new Exception("Package identity mismatch"); }
                    finally { Marshal.FreeHGlobal(packageInfo); }
                }
                finally { Marshal.FreeHGlobal(info); }
            }
            finally { CloseHandle(token); }
            for (int index = 0; index < aliases.Length; index++) { RequireDosExact(aliases[index].customName, aliases[index].customTarget); RequireDosExact(aliases[index].drive, aliases[index].driveTarget); VerifyAliasRoot(aliases[index]); }
            var cancelReader = new Thread(delegate() { string message = Console.ReadLine(); if (message == null || message == "cancel " + request.nonce) { Interlocked.Exchange(ref cancellation, 1); lock (jobGate) { if (job != IntPtr.Zero) TerminateJobObject(job, 125); } } }); cancelReader.IsBackground = true; cancelReader.Start();
            CloseHandle(write); write = IntPtr.Zero; CloseHandle(inputRead); inputRead = IntPtr.Zero; IntPtr outputHandle = read; read = IntPtr.Zero;
            reader = new Thread(delegate() { using (var stream = new FileStream(new SafeFileHandle(outputHandle, true), FileAccess.Read)) using (var text = new StreamReader(stream, Encoding.UTF8)) { char[] buffer = new char[2048]; int count; while ((count = text.Read(buffer, 0, buffer.Length)) != 0) { output.Append(buffer, 0, count); if (output.Length > request.maxOutputChars) { truncated = true; output.Remove(0, output.Length - request.maxOutputChars); } } } }); reader.Start();
            if (ResumeThread(child.thread) == UInt32.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error(), "Resume isolated process");
            result["pid"] = child.pid; result["sandbox"] = "windows-lpac";
            uint wait = WaitForSingleObject(child.process, checked((uint)request.timeoutSeconds * 1000));
            if (wait == WaitTimeout) { result["error"] = "Command timed out"; Check(TerminateJobObject(job, 124), "Terminate timed out job"); if (WaitForSingleObject(child.process, 5000) != WaitObject0) throw new Exception("Timed out process did not terminate"); }
            else if (wait != WaitObject0) throw new Win32Exception(Marshal.GetLastWin32Error(), "Wait for isolated process");
            uint exit; Check(GetExitCodeProcess(child.process, out exit), "Read exit code"); result["exitCode"] = exit;
            for (int index = 0; index < aliases.Length; index++) { RequireDosExact(aliases[index].customName, aliases[index].customTarget); RequireDosExact(aliases[index].drive, aliases[index].driveTarget); VerifyAliasRoot(aliases[index]); }
            if (Interlocked.CompareExchange(ref cancellation, 0, 0) != 0) result["error"] = "Command cancelled";
        }
        catch (Exception error) { result["error"] = error.Message; result["exitCode"] = null; }
        finally
        {
            var failures = new List<string>(); bool jobEnded = true;
            lock (jobGate)
            {
                if (job != IntPtr.Zero)
                {
                    try { Check(TerminateJobObject(job, 125), "Terminate owned job"); WaitForEmptyJob(job, 5000); }
                    catch (Exception error) { jobEnded = false; failures.Add("Job: " + error.Message); }
                    finally { CloseHandle(job); job = IntPtr.Zero; }
                }
            }
            if (write != IntPtr.Zero) CloseHandle(write);
            if (reader != null && !reader.Join(5000))
            {
                result["error"] = CombineDiagnostic(result.ContainsKey("error") && result["error"] != null ? result["error"].ToString() : null, "Output reader did not terminate");
            }
            if (child.thread != IntPtr.Zero) CloseHandle(child.thread); if (child.process != IntPtr.Zero) CloseHandle(child.process); if (read != IntPtr.Zero) CloseHandle(read); if (inputRead != IntPtr.Zero) CloseHandle(inputRead); if (inputWrite != IntPtr.Zero) CloseHandle(inputWrite);
            if (attributesInitialized) DeleteProcThreadAttributeList(attributes);
            foreach (IntPtr pointer in new IntPtr[] { attributes, capabilityData, capabilityList, lpacData, handleData, jobData, envData }) if (pointer != IntPtr.Zero) Marshal.FreeHGlobal(pointer);
            foreach (IntPtr capability in capabilitySids) if (capability != IntPtr.Zero) LocalFree(capability);
            if (jobEnded)
            {
                if (aliases != null) try { RemoveAliases(aliases); result["aliasesDeleted"] = true; } catch (Exception error) { failures.Add("DOS aliases: " + error.Message); } finally { ReleaseAliasGates(aliases); }
                if (nullDeviceGranted) try { ReconcileRecoveryNullDeviceGrant(identity); } catch (Exception error) { failures.Add("Null device: " + error.Message); }
                for (int index = applied.Count - 1; index >= 0; index--) try { Access(applied[index], identity, false); } catch (Exception error) { failures.Add("ACL " + index.ToString() + ": " + error.Message); }
                if (profileCreated) try { DeleteProfile(profile); result["profileDeleted"] = true; } catch (Exception error) { failures.Add("Profile: " + error.Message); }
                if (failures.Count == 0 && leaseWritten && lease != null && lease.mcpCustody != null)
                {
                    try
                    {
                        string qReason;
                        McpCustodyOutcome outcome = RestoreOrQuarantineMcpConfigCustody(lease, canonicalState, controller.user, mcpHold, serializer, out qReason);
                        mcpHold = null;
                        if (outcome == McpCustodyOutcome.Restored)
                        {
                            result["mcpConfigCustodyRestored"] = true;
                        }
                        else
                        {
                            result["error"] = CombineDiagnostic(
                                result.ContainsKey("error") && result["error"] != null ? result["error"].ToString() : null,
                                "Managed MCP config restore conflict (" + qReason + "); verified original preserved in secure bridge quarantine");
                        }
                    }
                    catch (Exception error) { failures.Add("MCP config custody: " + error.Message); }
                }
            }
            else if (aliases != null) ReleaseAliasGates(aliases);
            if (mcpHold != null) { mcpHold.Dispose(); mcpHold = null; }
            for (int index = pins.Count - 1; index >= 0; index--) pins[index].Dispose();
            if (sid != IntPtr.Zero) FreeSid(sid);
            if (leaseFile != null && leaseWritten)
            {
                if (failures.Count == 0 && (profileCreated || (lease != null && lease.mcpCustody != null))) { try { File.Delete(leaseFile); } catch (Exception error) { failures.Add("Lease: " + error.Message); } }
                if (failures.Count != 0) try { if (lease != null && !String.IsNullOrEmpty(lease.sid)) { lease.phase = "cleanup-failed"; WriteLease(leaseFile, lease, false, serializer); } } catch (Exception error) { failures.Add("Lease: " + error.Message); }
            }
            if (failures.Count != 0)
            {
                result["error"] = CombineDiagnostic(result.ContainsKey("error") && result["error"] != null ? result["error"].ToString() : null, "Cleanup failed: " + String.Join("; ", failures.ToArray()));
            }
        }
        result["output"] = output.ToString(); result["truncated"] = truncated; Console.WriteLine(serializer.Serialize(result)); return result.ContainsKey("error") ? 1 : 0;
    }
}
