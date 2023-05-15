#[test]
fn test_sysboostd_setup() {
    // Check if sysboostd is running
    let sysboostd_running = is_sysboostd_running();
    assert!(sysboostd_running, "sysboostd is not running");

    // Create config file
    let config_file_path = "/etc/sysboost.d/test.conf";
    let mut config_file = match File::create(config_file_path) {
        Ok(file) => file,
        Err(e) => {
            panic!("Failed to create config file: {}", e);
        }
    };
    writeln!(config_file, "elf_path = \"/usr/bin/bash\"").unwrap();
    writeln!(config_file, "mode = \"static\"").unwrap();
    writeln!(config_file, "libs = \"/usr/lib64/libtinfo.so.6\"").unwrap();

    // Restart sysboostd service
    let output = Command::new("systemctl")
        .args(&["restart", "sysboostd.service"])
        .output()
        .expect("Failed to execute command");
    assert!(
        output.status.success(),
        "Failed to restart sysboostd service: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check if bash.rto is generated
    let bash_rto_path = "/usr/bin/bash.rto";
    let bash_rto_exists = std::path::Path::new(bash_rto_path).exists();
    assert!(bash_rto_exists, "bash.rto is not generated");
}

fn is_sysboostd_running() -> bool {
    // Start sysboostd service if it's not running
    let output = Command::new("systemctl")
        .args(&["is-active", "sysboostd.service"])
        .output()
        .expect("Failed to execute command");

    if !output.status.success() {
        let output = Command::new("systemctl")
            .args(&["start", "sysboostd.service"])
            .output()
            .expect("Failed to execute command");
        if !output.status.success() {
            panic!("Failed to start sysboostd service: {}", String::from_utf8_lossy(&output.stderr));
        }
    }

    // Check if sysboostd is running
    let output = Command::new("systemctl")
        .args(&["is-active", "sysboostd.service"])
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let status = stdout.trim();
        return status == "active";
    }

    false
}