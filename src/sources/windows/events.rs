// SPDX-License-Identifier: MIT
//! Event log queries (wevtutil) within the time window.

use std::time::Duration;

/// The default event log window: 72 hours.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(72 * 3600);

/// `window` in whole milliseconds for `timediff`, saturating at `u64::MAX`.
pub fn window_ms(window: Option<Duration>) -> u64 {
    u64::try_from(window.unwrap_or(DEFAULT_WINDOW).as_millis()).unwrap_or(u64::MAX)
}

/// The wevtutil XPath query for display, power and hardware-error events in the System log of the
/// last `window_ms` milliseconds.
pub fn system_events_query(window_ms: u64) -> String {
    format!(
        "/q:*[System[(Provider[@Name='Display'] or Provider[@Name='Microsoft-Windows-DxgKrnl'] or \
Provider[@Name='Microsoft-Windows-Kernel-PnP'] or Provider[@Name='Microsoft-Windows-WHEA-Logger'] or \
Provider[@Name='Microsoft-Windows-Kernel-Power'] or Provider[@Name='BugCheck'] or \
Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] or Provider[@Name='Microsoft-Windows-Kernel-LiveDump'] or \
Provider[@Name='igfx'] or Provider[@Name='igfxn']) and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
    )
}

/// The wevtutil XPath query for application crash and error-reporting events of the last
/// `window_ms` milliseconds.
pub fn application_events_query(window_ms: u64) -> String {
    format!(
        "/q:*[System[Provider[@Name='Application Error' or @Name='Windows Error Reporting'] \
and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
    )
}

/// The longest window the channel script looks back (ten years), so the start time stays a valid date.
const MAX_SCRIPT_WINDOW_MS: u64 = 315_360_000_000;

/// The PowerShell script that reads the last `window_ms` milliseconds (at most 200 events per
/// channel) of every enabled event channel whose name mentions DxgKrnl, the Desktop Window
/// Manager, live kernel dumps or the display, one line per event. The channel names are found on
/// the machine rather than assumed. Only single quotes are used.
pub fn graphics_channels_script(window_ms: u64) -> String {
    let window_ms = window_ms.min(MAX_SCRIPT_WINDOW_MS);
    format!(
        "$start = (Get-Date).AddMilliseconds(-{window_ms}); \
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | \
Where-Object {{ $_.IsEnabled -and $_.LogName -match 'dxgkrnl|dwm|livedump|display' }} | \
ForEach-Object {{ $name = $_.LogName; \
$events = Get-WinEvent -FilterHashtable @{{LogName=$name; StartTime=$start}} -MaxEvents 200 -ErrorAction SilentlyContinue; \
if ($events) {{ '== ' + $name + ' =='; \
$events | ForEach-Object {{ $_.TimeCreated.ToString('o') + ' ' + $_.Id + ' ' + $_.LevelDisplayName + ' ' + \
$_.ProviderName + ': ' + ($_.Message -replace '\\s+', ' ') }} }} }}"
    )
}

/// The wevtutil XPath query for every event of the last `window_ms` milliseconds.
pub fn time_window_query(window_ms: u64) -> String {
    format!("/q:*[System[TimeCreated[timediff(@SystemTime) <= {window_ms}]]]")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "events_tests.rs"]
mod tests;
