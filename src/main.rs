// SPDX-License-Identifier: MIT
//! The `xe-bug-report` binary: parse arguments, collect, print, exit.
//!
//! All work happens in [`real_main`], which returns the exit code; only then does `main` call
//! `std::process::exit`, so every destructor (the private temporary directories, the partial
//! archive) has run before the process ends.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use xe_bug_report::bundle::collect::remove_outstanding_temp_dirs;
use xe_bug_report::bundle::manifest::json_text;
use xe_bug_report::bundle::summary::{
    JSON_INDENT, display_path, format_report, format_source_list, json_error, json_result,
};
use xe_bug_report::bundle::writer::{
    BACKSTOP_EXIT_CODE, BACKSTOP_GRACE, BundleRequest, default_bundle_name, remove_leftovers, spawn_backstop,
    write_bundle,
};
use xe_bug_report::cli::{self, Args, CliExit, USAGE_HINT};
use xe_bug_report::guard::Guard;
use xe_bug_report::procio::find_in_path;
use xe_bug_report::redact::Rules;
use xe_bug_report::{GpuDevice, SourceOptions, diag, sources};

/// Process exit code of a failed run.
const EXIT_FAILURE: i32 = 1;
/// The prefix of plain-text error messages.
const ERROR_PREFIX: &str = "xe-bug-report: ";
/// How long the PCI enumeration may take.
const ENUMERATION_LIMIT: Duration = Duration::from_secs(5);

fn main() {
    std::process::exit(real_main());
}

/// Writes `text` to stdout; a closed pipe is not an error worth a panic.
fn out(text: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

/// Writes `text` to stderr.
fn err(text: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

/// The error report in the format the caller asked for: a pretty JSON object (for stdout) with
/// `json`, else a line for stderr. Both end with a newline.
fn error_report(json: bool, message: &str) -> String {
    if json {
        format!("{}\n", json_text(&json_error(message), JSON_INDENT))
    } else {
        format!("{ERROR_PREFIX}{message}\n")
    }
}

/// Prints `message` as the run's error and returns the exit code.
fn fail(json: bool, message: &str) -> i32 {
    if json {
        out(&error_report(true, message));
    } else {
        err(&error_report(false, message));
    }
    EXIT_FAILURE
}

/// The xpu-smi executable: the `--xpu-smi` path when it is a file (a bare name is also looked up
/// on PATH), else the default search. None when there is none; an explicit path that does not
/// exist is reported once on stderr.
fn resolve_xpu_smi(explicit: Option<&Path>) -> Option<PathBuf> {
    let found = sources::find_xpu_smi(explicit);
    let Some(path) = explicit else { return found };
    if found.is_some() {
        return found;
    }
    let on_path = path.to_str().filter(|name| !name.contains(['/', '\\'])).and_then(find_in_path);
    if on_path.is_none() {
        log::warn!("--xpu-smi {}: not an existing file; the xpu-smi sources are skipped", display_path(path));
    }
    on_path
}

/// The GPUs the OS reports; the enumeration reads sysfs (or runs a query), so it is guarded like
/// every other read.
fn enumerate_gpus() -> Vec<GpuDevice> {
    let found = Guard::new(ENUMERATION_LIMIT).bounded("enumeration", sources::gpus_from_os);
    if found.is_none() {
        log::warn!("the PCI enumeration did not finish; no GPU is assumed present");
    }
    found.unwrap_or_default()
}

/// `--timeout` as an absolute deadline; None when it is disabled or too far away to represent.
fn deadline_of(args: &Args) -> Option<Instant> {
    args.timeout.and_then(|timeout| Instant::now().checked_add(timeout))
}

/// How long the backstop waits for its message to reach stderr before it exits anyway.
const BACKSTOP_MESSAGE_WAIT: Duration = Duration::from_secs(1);

/// Arms the backstop: `BACKSTOP_GRACE` after `deadline` it cleans up (the command output
/// directories and, with `output`, `<output>.partial`), prints a message on a throw-away thread
/// (a full stderr pipe must not keep the process alive; it waits at most one second) and exits 124.
///
/// Limits: child processes keep running after the exit (each is in its own process group and
/// there is no registry of them), and a child stuck in the kernel cannot be killed in any case.
fn start_backstop(deadline: Instant, output: Option<PathBuf>) {
    let started = spawn_backstop(deadline, BACKSTOP_GRACE, move || {
        match &output {
            Some(output) => remove_leftovers(output),
            None => remove_outstanding_temp_dirs(),
        }
        let (done, wait) = std::sync::mpsc::channel();
        let printer = std::thread::Builder::new().spawn(move || {
            err(&format!("{ERROR_PREFIX}the collection did not finish in time\n"));
            let _ = done.send(());
        });
        if printer.is_ok() {
            let _ = wait.recv_timeout(BACKSTOP_MESSAGE_WAIT);
        }
        std::process::exit(BACKSTOP_EXIT_CODE);
    });
    if started.is_err() {
        log::warn!("cannot start the backstop thread; the deadline is only checked between sources");
    }
}

/// Runs the tool and returns its exit code.
fn real_main() -> i32 {
    let args = match cli::parse_args(std::env::args_os()) {
        Ok(args) => args,
        Err(CliExit::Help(text)) => {
            out(&text);
            return 0;
        }
        Err(CliExit::Version(text)) => {
            out(&format!("{text}\n"));
            return 0;
        }
        Err(CliExit::Usage { message, json }) => {
            let code = fail(json, &message);
            if !json {
                err(&format!("{USAGE_HINT}\n"));
            }
            return code;
        }
    };
    diag::init(args.verbose);
    run(&args)
}

/// Lists or collects as `args` ask and returns the exit code.
fn run(args: &Args) -> i32 {
    // Before the first filesystem probe: PATH lookups and PCI enumeration are not guarded, so a
    // stalled mount must still end in exit 124. `--list` is covered too (it has no archive).
    let deadline = deadline_of(args);
    let output = args.output.clone().unwrap_or_else(|| PathBuf::from(default_bundle_name(SystemTime::now())));
    if let Some(deadline) = deadline {
        start_backstop(deadline, (!args.list).then(|| output.clone()));
    }

    let devices = match cli::select_devices(&args.devices, enumerate_gpus()) {
        Ok(devices) => devices,
        Err(error) => return fail(args.json, &error.to_string()),
    };
    let options = SourceOptions {
        profile: args.profile,
        devices,
        samples: args.samples,
        since: args.since,
        xpu_smi: resolve_xpu_smi(args.xpu_smi.as_deref()),
    };

    if args.list {
        out(&format_source_list(&sources::sources(&options)));
        return 0;
    }

    let request = BundleRequest {
        output,
        options,
        rules: if args.no_redact { Rules::none() } else { Rules::default() },
        deadline,
    };
    log::debug!(
        "output: {}, redact: {}, json: {}",
        display_path(&request.output),
        !args.no_redact,
        args.json
    );

    let result = match write_bundle(&request) {
        Ok(result) => result,
        Err(error) => return fail(args.json, &error.to_string()),
    };
    if args.json {
        out(&format!("{}\n", json_text(&json_result(&result, &request.output), JSON_INDENT)));
    } else {
        out(&format_report(&result, &request.output, sources::current_privilege(), args.verbose));
    }
    0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "main_tests.rs"]
mod tests;
