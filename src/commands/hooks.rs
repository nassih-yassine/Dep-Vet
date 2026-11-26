//! `dep-vet hook`: the Claude Code PreToolUse hook and its settings merge.

pub fn run_guard_child(command: &str) -> (u8, Option<String>) {
    use std::io::Read as _;
    use std::process::{Command as Process, Stdio};

    let Ok(executable) = std::env::current_exe() else {
        return (3, None);
    };
    // The guard caps at the same boundary; do it before argv so a huge hook
    // input cannot hit E2BIG.
    let (command, _) = dep_vet::intent::cap_command(command);
    let mut child = Process::new(executable);
    // Pass the command on stdin: Windows caps a process command line at about
    // 32,767 characters, so a large command cannot be one argv element.
    child
        .args(["guard", "--check", "--json", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if key.starts_with("DEPVET_")
            && !matches!(key.as_ref(), "DEPVET_CACHE_DIR" | "DEPVET_DEBUG")
        {
            child.env_remove(key.as_ref());
        }
    }
    // Test seam: debug builds only. The hook otherwise ignores agent-settable
    // registry overrides, so `tests/cli.rs` must be able to point the child at
    // its local fake registry without weakening a release binary.
    if cfg!(debug_assertions)
        && let Some(test_base) = std::env::var_os("DEPVET_HOOK_TEST_BASE")
    {
        child
            .env("DEPVET_REGISTRY_BASE", &test_base)
            .env(
                "DEPVET_DOWNLOADS_BASE",
                format!("{}/downloads", test_base.to_string_lossy()),
            )
            .env("DEPVET_OSV_BASE", &test_base)
            .env("DEPVET_SCORECARD_BASE", &test_base)
            .env("DEPVET_EPSS_BASE", &test_base)
            .env(
                "DEPVET_KEV_BASE",
                format!("{}/kev.json", test_base.to_string_lossy()),
            )
            .env("DEPVET_NO_CACHE", "1")
            .env("DEPVET_ALLOW_INSECURE_BASES", "1");
    }
    let Ok(mut child) = child.spawn() else {
        return (3, None);
    };
    if let Some(mut input) = child.stdin.take() {
        use std::io::Write as _;
        let _ = input.write_all(command.as_bytes());
        // Dropping closes the pipe so the child sees EOF.
    }
    // Drain stdout concurrently: a report larger than the pipe buffer would
    // otherwise block the child while we wait for it to exit, and the deadline
    // would turn a real verdict into "allow".
    let mut pipe = match child.stdout.take() {
        Some(pipe) => pipe,
        None => return (3, None),
    };
    let reader = std::thread::spawn(move || {
        let mut body = String::new();
        let _ = pipe.read_to_string(&mut body);
        body
    });

    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(dep_vet::hook::HOOK_BUDGET_SECONDS);
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                timed_out = true;
                break;
            }
            Err(_) => {
                let _ = child.kill();
                timed_out = true;
                break;
            }
        }
    }
    let status = child.wait().ok();
    let body = reader.join().unwrap_or_default();
    if timed_out {
        return (3, None);
    }
    (
        status.and_then(|status| status.code()).unwrap_or(3) as u8,
        Some(body),
    )
}

fn hook_settings_path(project: bool, user: bool) -> anyhow::Result<std::path::PathBuf> {
    if project && user {
        anyhow::bail!("choose either --project or --user");
    }
    if user {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| anyhow::anyhow!("could not find the home directory"))?;
        return Ok(std::path::PathBuf::from(home)
            .join(".claude")
            .join("settings.json"));
    }
    Ok(std::path::PathBuf::from(".claude").join("settings.json"))
}

pub fn install(
    target: &str,
    project: bool,
    user: bool,
    strict: bool,
    write: bool,
) -> anyhow::Result<u8> {
    if target != "claude" {
        anyhow::bail!("unknown hook target '{target}'; supported: claude");
    }
    let path = hook_settings_path(project, user)?;
    let before = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let executable = std::env::current_exe()?;
    let command = dep_vet::hook::settings::command_line(&executable, strict);
    let after = dep_vet::hook::settings::merge(
        &path.display().to_string(),
        &before,
        &command,
        dep_vet::hook::settings::TIMEOUT_SECONDS,
    )?;
    println!(
        "{}\n{}",
        path.display(),
        dep_vet::hook::settings::diff(&before, &after)
    );
    if write {
        dep_vet::hook::settings::atomic_write(&path, &after)?;
        println!("wrote {}", path.display());
    } else {
        println!("dry run; pass --write to save");
    }
    Ok(0)
}

pub fn uninstall(target: &str, project: bool, user: bool, write: bool) -> anyhow::Result<u8> {
    if target != "claude" {
        anyhow::bail!("unknown hook target '{target}'; supported: claude");
    }
    let path = hook_settings_path(project, user)?;
    let before = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let executable = std::env::current_exe()?;
    for strict in [false, true] {
        let command = dep_vet::hook::settings::command_line(&executable, strict);
        let after =
            dep_vet::hook::settings::remove(&path.display().to_string(), &before, &command)?;
        if after != before {
            println!(
                "{}\n{}",
                path.display(),
                dep_vet::hook::settings::diff(&before, &after)
            );
            if write {
                dep_vet::hook::settings::atomic_write(&path, &after)?;
                println!("wrote {}", path.display());
            } else {
                println!("dry run; pass --write to save");
            }
            return Ok(0);
        }
    }
    println!("no dep-vet hook in {}", path.display());
    Ok(0)
}

pub fn run(strict: bool) -> anyhow::Result<u8> {
    use std::io::Read as _;
    let mut stdin = std::io::stdin().take(dep_vet::hook::MAX_STDIN_BYTES + 1);
    let mut body = String::new();
    let _ = stdin.read_to_string(&mut body);
    let Some(command) = dep_vet::hook::read_command(&body) else {
        return Ok(0);
    };
    let (exit_code, guard_json) = run_guard_child(&command);
    if exit_code == 3 && !strict && std::env::var_os("DEPVET_DEBUG").is_some() {
        for note in dep_vet::hook::notes(guard_json.as_deref()) {
            eprintln!("dep-vet hook: not checked: {note}");
        }
    }
    let decision = dep_vet::hook::decide(exit_code, guard_json.as_deref(), strict);
    if let Some(output) = dep_vet::hook::render(&decision) {
        println!("{output}");
    }
    Ok(0)
}
