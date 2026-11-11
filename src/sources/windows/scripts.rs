// SPDX-License-Identifier: MIT
//! PowerShell scripts for the rows that need more than one native command.
//!
//! Every script is passed to `powershell.exe -Command` as one argument, so none contains a double
//! quote (command-line quoting could damage it) or ends in a backslash; strings use single
//! quotes. Each prints plain text and never fails the whole script when one query is missing.

/// The Khronos loader registry keys (OpenCL vendors, Vulkan drivers and layers; both registry
/// views and the current user), with the target of each entry: the file version of a library,
/// or the manifest's library and its version.
pub const KHRONOS_ICDS: &str = concat!(
    r"function Get-FileVer($p) { $f = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue; ",
    r"if ($f) { 'file version ' + $f.VersionInfo.FileVersion + ', product version ' + $f.VersionInfo.ProductVersion } ",
    r"else { 'file not found' } }; ",
    r"$keys = 'HKLM:\SOFTWARE\Khronos\OpenCL\Vendors', 'HKLM:\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors', ",
    r"'HKLM:\SOFTWARE\Khronos\Vulkan\Drivers', 'HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\Drivers', ",
    r"'HKLM:\SOFTWARE\Khronos\Vulkan\ImplicitLayers', 'HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers', ",
    r"'HKLM:\SOFTWARE\Khronos\Vulkan\ExplicitLayers', 'HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\ExplicitLayers', ",
    r"'HKCU:\SOFTWARE\Khronos\Vulkan\Drivers', 'HKCU:\SOFTWARE\Khronos\Vulkan\ImplicitLayers', ",
    r"'HKCU:\SOFTWARE\Khronos\Vulkan\ExplicitLayers'; ",
    r"foreach ($k in $keys) { ",
    r"$item = Get-Item -Path $k -ErrorAction SilentlyContinue; ",
    r"if ($null -eq $item) { '[' + $k + '] not present'; continue }; ",
    r"'[' + $k + ']'; ",
    r"foreach ($n in $item.GetValueNames()) { ",
    r"'  ' + $n + ' = ' + $item.GetValue($n); ",
    r"if ($n -eq '') { continue }; ",
    r"$path = $n; ",
    r"if (-not [IO.Path]::IsPathRooted($n)) { $path = Join-Path (Join-Path $env:SystemRoot 'System32') $n }; ",
    r"$f = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue; ",
    r"if ($null -eq $f) { '    ' + $path + ' not found'; continue }; ",
    r"if ($f.Extension -eq '.dll') { '    ' + (Get-FileVer $path) } ",
    r"elseif ($f.Extension -eq '.json') { ",
    r"$j = $null; try { $j = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } catch { }; ",
    r"$entry = $null; if ($j.ICD) { $entry = $j.ICD } elseif ($j.layer) { $entry = $j.layer } ",
    r"elseif ($j.layers) { $entry = @($j.layers)[0] }; ",
    r"if ($entry) { ",
    r"'    name ' + $entry.name + ', api_version ' + $entry.api_version + ', implementation_version ' + $entry.implementation_version; ",
    r"$lib = $entry.library_path; ",
    r"if ($lib) { $full = $lib; ",
    r"if (-not [IO.Path]::IsPathRooted($lib)) { $full = Join-Path (Split-Path $path) $lib; ",
    r"if (-not (Test-Path -LiteralPath $full)) { $full = Join-Path (Join-Path $env:SystemRoot 'System32') $lib } }; ",
    r"'    library ' + $lib + ': ' + (Get-FileVer $full) } } } } }"
);

/// The user-mode driver libraries (graphics, compute, media and loader libraries by name pattern)
/// in System32, SysWOW64 and the eight newest Intel driver packages of the driver store
/// (`iigd*` folders, where the display driver package keeps them), with file and product
/// versions, size and write time.
pub const UMD_VERSIONS: &str = concat!(
    r"$dirs = @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64')); ",
    r"Get-ChildItem -Path (Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository') -Directory -Filter 'iigd*' ",
    r"-ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 8 | ",
    r"ForEach-Object { $dirs += $_.FullName }; ",
    r"$patterns = 'igd*.dll', 'igc*.dll', 'igvk*.dll', 'ze_*.dll', 'OpenCL.dll', 'vulkan-1.dll', ",
    r"'libmfx*.dll', 'mfx*.dll', 'libvpl*.dll'; ",
    r"foreach ($d in $dirs) { '[' + $d + ']'; ",
    r"foreach ($p in $patterns) { ",
    r"Get-ChildItem -Path (Join-Path $d $p) -ErrorAction SilentlyContinue | ForEach-Object { ",
    r"'  ' + $_.Name + ' ' + $_.VersionInfo.FileVersion + ' (product ' + $_.VersionInfo.ProductVersion + '), ' + ",
    r"$_.Length + ' bytes, ' + $_.LastWriteTimeUtc.ToString('o') } } }"
);

/// One sample (two readings a second apart, the second used) of the GPU engine utilisation and
/// GPU memory counters, only the non-zero ones, with the machine name left out of the counter
/// paths, then the names of the processes that appear in the instance names.
pub const GPU_COUNTERS: &str = concat!(
    r"$c = Get-Counter -Counter '\GPU Engine(*)\Utilization Percentage', '\GPU Adapter Memory(*)\Dedicated Usage', ",
    r"'\GPU Adapter Memory(*)\Shared Usage', '\GPU Process Memory(*)\Dedicated Usage', ",
    r"'\GPU Process Memory(*)\Shared Usage' -SampleInterval 1 -MaxSamples 2 -ErrorAction SilentlyContinue; ",
    r"if ($null -eq $c) { 'the GPU performance counters are not available' } else { ",
    r"$pids = @{}; ",
    r"@($c)[-1].CounterSamples | Where-Object { $_.CookedValue -gt 0 } | ForEach-Object { ",
    r"($_.Path -replace '^\\\\[^\\]+', '') + ' = ' + [math]::Round($_.CookedValue, 2); ",
    r"if ($_.InstanceName -match 'pid_(\d+)_') { $pids[[int]$Matches[1]] = 1 } }; ",
    r"if ($pids.Count -gt 0) { '== processes =='; ",
    r"Get-Process -Id ([int[]]@($pids.Keys)) -ErrorAction SilentlyContinue | ForEach-Object { ",
    r"'pid ' + $_.Id + ' ' + $_.ProcessName } } }"
);

/// Intel packages installed for the current user (Appx name and version) and Intel entries in the
/// installed-programs registry (name and version only).
pub const INTEL_SOFTWARE: &str = concat!(
    r"'== Appx packages =='; ",
    r"Get-AppxPackage -Name '*Intel*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + ' ' + $_.Version }; ",
    r"'== installed programs =='; ",
    r"Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', ",
    r"'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | ",
    r"Where-Object { $_.DisplayName -like '*Intel*' -or $_.DisplayName -like '*oneAPI*' } | ",
    r"ForEach-Object { $_.DisplayName + ' ' + $_.DisplayVersion } | Sort-Object -Unique"
);

/// Monitors from WMI: identification (manufacturer, product code, friendly name, year and week;
/// the serial number is never read), basic parameters, connection type and the legacy desktop
/// monitor class. The identification arrays are decoded from character codes.
pub const MONITORS: &str = concat!(
    r"$dec = { param($a) -join ([char[]]($a | Where-Object { $_ -ne 0 })) }; ",
    r"$tech = @{0='VGA'; 1='S-video'; 2='composite'; 3='component'; 4='DVI'; 5='HDMI'; 6='LVDS'; 8='D-Jpn'; ",
    r"9='SDI'; 10='DisplayPort'; 11='DisplayPort (embedded)'; 12='UDI'; 13='UDI (embedded)'; 14='SDTV dongle'; ",
    r"15='Miracast'; 16='indirect wired'}; ",
    r"'== WmiMonitorID =='; ",
    r"Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorID -ErrorAction SilentlyContinue | ForEach-Object { ",
    r"$_.InstanceName + ' | ' + (& $dec $_.ManufacturerName) + ' | ' + (& $dec $_.ProductCodeID) + ' | ' + ",
    r"(& $dec $_.UserFriendlyName) + ' | made ' + $_.YearOfManufacture + ' week ' + $_.WeekOfManufacture }; ",
    r"'== WmiMonitorBasicDisplayParams =='; ",
    r"Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue | ",
    r"ForEach-Object { $_.InstanceName + ' | active ' + $_.Active + ' | size cm ' + $_.MaxHorizontalImageSize + 'x' + ",
    r"$_.MaxVerticalImageSize + ' | digital input ' + $_.VideoInputType }; ",
    r"'== WmiMonitorConnectionParams =='; ",
    r"Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue | ",
    r"ForEach-Object { $n = [int64]$_.VideoOutputTechnology; $name = 'technology ' + $n; ",
    r"if ($n -eq 2147483648) { $name = 'internal' } elseif ($n -eq 4294967295) { $name = 'other' } ",
    r"elseif ($n -ge 0 -and $n -le 16 -and $tech.ContainsKey([int]$n)) { $name = $tech[[int]$n] }; ",
    r"$_.InstanceName + ' | ' + $name }; ",
    r"'== Win32_DesktopMonitor =='; ",
    r"Get-CimInstance Win32_DesktopMonitor -ErrorAction SilentlyContinue | ",
    r"Format-List Name,MonitorType,MonitorManufacturer,ScreenWidth,ScreenHeight,PixelsPerXLogicalInch,Status"
);

/// Virtualization-based security and code integrity state (Device Guard WMI class) and whether a
/// hypervisor is present.
pub const ISOLATION: &str = concat!(
    r"'== Win32_DeviceGuard =='; ",
    r"$dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard ",
    r"-ErrorAction SilentlyContinue; ",
    r"if ($dg) { $dg | Format-List AvailableSecurityProperties,",
    r"CodeIntegrityPolicyEnforcementStatus,RequiredSecurityProperties,SecurityServicesConfigured,",
    r"SecurityServicesRunning,UsermodeCodeIntegrityPolicyEnforcementStatus,VirtualizationBasedSecurityStatus,",
    r"SmmIsolationLevel } ",
    r"else { 'Win32_DeviceGuard returned nothing (it needs an elevated prompt, or this Windows has no VBS support)' }; ",
    r"'== Win32_ComputerSystem =='; ",
    r"Get-CimInstance Win32_ComputerSystem | Format-List Manufacturer,Model,HypervisorPresent"
);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "scripts_tests.rs"]
mod tests;
