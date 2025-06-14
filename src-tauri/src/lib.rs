use flate2::read::GzDecoder;
use futures_util::StreamExt;
use regex::Regex;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use tar::Archive;
use tauri::{AppHandle, Emitter, State};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// Struct to hold the Suricata process handle
struct SuricataProcess {
    handle: Option<tokio::process::Child>,
}

// Struct to manage eve.json tailing
struct EveJsonTailer {
    is_running: Arc<Mutex<bool>>,
}

// Struct to hold the EveBox process handle
struct EveBoxProcess {
    handle: Option<tokio::process::Child>,
}

// Helper function to strip ANSI color codes from terminal output
fn strip_ansi_codes(text: &str) -> String {
    let re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(text, "").to_string()
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn get_network_interfaces() -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        use std::str;

        // Run getmac /v to get adapter GUIDs
        let getmac_output = Command::new("getmac")
            .args(&["/v", "/fo", "list"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("Failed to run getmac: {}", e))?;

        // Run ipconfig /all to get detailed network information
        let ipconfig_output = Command::new("ipconfig")
            .args(&["/all"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("Failed to run ipconfig: {}", e))?;

        if !ipconfig_output.status.success() {
            return Err("ipconfig command failed".to_string());
        }

        // Parse getmac output to build adapter name to GUID mapping
        let getmac_str = str::from_utf8(&getmac_output.stdout)
            .map_err(|e| format!("Failed to parse getmac output: {}", e))?;

        let mut adapter_guids: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut current_connection: Option<String> = None;

        for line in getmac_str.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("Connection Name:") {
                current_connection = trimmed.split(':').nth(1).map(|s| s.trim().to_string());
            } else if trimmed.starts_with("Transport Name:") {
                let current_transport = trimmed.split(':').nth(1).map(|s| s.trim().to_string());

                // Extract GUID from transport name
                if let (Some(conn), Some(trans)) = (&current_connection, &current_transport) {
                    if let Some(guid_start) = trans.find('{') {
                        if let Some(guid_end) = trans.find('}') {
                            let guid = trans[guid_start..=guid_end].to_string();
                            adapter_guids.insert(conn.clone(), guid);
                        }
                    }
                }
            }
        }

        // Convert ipconfig output to string
        let ipconfig_str = str::from_utf8(&ipconfig_output.stdout)
            .map_err(|e| format!("Failed to parse ipconfig output: {}", e))?;

        let mut interfaces = Vec::new();
        let mut current_adapter: Option<String> = None;
        let mut current_ip: Option<String> = None;

        // Parse the ipconfig output line by line
        for line in ipconfig_str.lines() {
            let trimmed = line.trim();

            // Check for Ethernet adapter lines
            if trimmed.starts_with("Ethernet adapter") && trimmed.ends_with(":") {
                // Save previous adapter if it has an IP
                if let (Some(adapter), Some(ip)) = (current_adapter.take(), current_ip.take()) {
                    // Try to find the GUID for this adapter
                    let guid = adapter_guids
                        .get(&adapter)
                        .cloned()
                        .unwrap_or_else(|| "GUID not found".to_string());
                    interfaces.push(format!("{} - {} - {}", adapter, ip, guid));
                }

                // Extract adapter name
                let adapter_name = trimmed
                    .strip_prefix("Ethernet adapter ")
                    .and_then(|s| s.strip_suffix(":"))
                    .unwrap_or(trimmed);
                current_adapter = Some(adapter_name.to_string());
            }
            // Look for IPv4 address
            else if trimmed.starts_with("IPv4 Address") || trimmed.starts_with("IP Address") {
                if let Some(ip_part) = trimmed.split(':').nth(1) {
                    let ip = ip_part.trim().trim_end_matches("(Preferred)");
                    current_ip = Some(ip.to_string());
                }
            }
            // Check for Autoconfiguration IPv4 Address (fallback)
            else if current_ip.is_none() && trimmed.starts_with("Autoconfiguration IPv4 Address")
            {
                if let Some(ip_part) = trimmed.split(':').nth(1) {
                    let ip = ip_part.trim().trim_end_matches("(Preferred)");
                    current_ip = Some(ip.to_string());
                }
            }
        }

        // Don't forget the last adapter
        if let (Some(adapter), Some(ip)) = (current_adapter, current_ip) {
            let guid = adapter_guids
                .get(&adapter)
                .cloned()
                .unwrap_or_else(|| "GUID not found".to_string());
            interfaces.push(format!("{} - {} - {}", adapter, ip, guid));
        }

        // If no interfaces found, return an error
        if interfaces.is_empty() {
            Ok(vec!["No Ethernet adapters found".to_string()])
        } else {
            Ok(interfaces)
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("This feature is only available on Windows".to_string())
    }
}

#[tauri::command]
async fn install_suricata(app: AppHandle) -> Result<String, String> {
    // URL for Suricata installer
    let url = "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.10-1-64bit.msi";

    // Get Downloads directory and create file path
    let downloads_dir =
        dirs::download_dir().ok_or_else(|| "Could not find Downloads directory".to_string())?;
    let installer_path = downloads_dir.join("Suricata-7.0.10-1-64bit.msi");

    // Download the installer
    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("Failed to download: HTTP {}", response.status()));
    }

    // Get the content length for progress tracking
    let total_size = response.content_length().unwrap_or(0);

    // Create the file
    let mut file = tokio::fs::File::create(&installer_path)
        .await
        .map_err(|e| e.to_string())?;

    // Stream the download to file
    let mut stream = response.bytes_stream();
    let mut downloaded = 0u64;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .map_err(|e| e.to_string())?;
        downloaded += chunk.len() as u64;

        // Emit progress event
        if total_size > 0 {
            let progress = (downloaded as f64 / total_size as f64 * 100.0) as u32;
            app.emit("download-progress-suricata", progress).ok();
        }
    }

    // Ensure file is flushed and closed
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|e| e.to_string())?;
    drop(file);

    // Small delay to ensure file system has released the file
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Launch the installer
    #[cfg(target_os = "windows")]
    {
        Command::new("msiexec")
            .args(&["/i", installer_path.to_str().unwrap()])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        return Err("This installer is only for Windows".to_string());
    }

    Ok(format!(
        "Suricata installer downloaded to: {} and launched",
        installer_path.display()
    ))
}

#[tauri::command]
async fn install_npcap(app: AppHandle) -> Result<String, String> {
    // URL for NPCap installer
    let url = "https://npcap.com/dist/npcap-1.82.exe";

    // Get Downloads directory and create file path
    let downloads_dir =
        dirs::download_dir().ok_or_else(|| "Could not find Downloads directory".to_string())?;
    let installer_path = downloads_dir.join("npcap-1.82.exe");

    // Download the installer
    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("Failed to download: HTTP {}", response.status()));
    }

    // Get the content length for progress tracking
    let total_size = response.content_length().unwrap_or(0);

    // Create the file
    let mut file = tokio::fs::File::create(&installer_path)
        .await
        .map_err(|e| e.to_string())?;

    // Stream the download to file
    let mut stream = response.bytes_stream();
    let mut downloaded = 0u64;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .map_err(|e| e.to_string())?;
        downloaded += chunk.len() as u64;

        // Emit progress event
        if total_size > 0 {
            let progress = (downloaded as f64 / total_size as f64 * 100.0) as u32;
            app.emit("download-progress-npcap", progress).ok();
        }
    }

    // Ensure file is flushed and closed
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|e| e.to_string())?;
    drop(file);

    // Small delay to ensure file system has released the file
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Launch the installer
    #[cfg(target_os = "windows")]
    {
        // Use cmd /c to launch the installer
        Command::new("cmd")
            .args(&["/c", "start", "", installer_path.to_str().unwrap()])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
            .map_err(|e| format!("Failed to launch installer: {}", e))?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        return Err("This installer is only for Windows".to_string());
    }

    Ok(format!(
        "NPCap installer downloaded to: {} and launched",
        installer_path.display()
    ))
}

#[tauri::command]
async fn install_evebox(app: AppHandle) -> Result<String, String> {
    // URL for EveBox download
    let url = "https://evebox.org/files/release/latest/evebox-0.20.5-windows-x64.zip";

    // Get user's home directory and create .meerkat-desktop\evebox\bin path
    let evebox_base_dir = std::env::var("USERPROFILE")
        .map(|home| format!(r"{}\.meerkat-desktop\evebox", home))
        .map_err(|_| "Could not find user profile directory".to_string())?;

    let evebox_bin_dir = format!(r"{}\bin", evebox_base_dir);

    // Create bin directory if it doesn't exist
    std::fs::create_dir_all(&evebox_bin_dir)
        .map_err(|e| format!("Failed to create evebox bin directory: {}", e))?;

    // Create temp paths
    let temp_zip_path = std::path::Path::new(&evebox_base_dir).join("evebox-temp.zip");
    let temp_extract_dir = std::path::Path::new(&evebox_base_dir).join("temp-extract");

    // Download the zip file
    let response = reqwest::get(url).await.map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("Failed to download: HTTP {}", response.status()));
    }

    // Get the content length for progress tracking
    let total_size = response.content_length().unwrap_or(0);

    // Create the temp file
    let mut file = tokio::fs::File::create(&temp_zip_path)
        .await
        .map_err(|e| e.to_string())?;

    // Stream the download to file
    let mut stream = response.bytes_stream();
    let mut downloaded = 0u64;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .map_err(|e| e.to_string())?;
        downloaded += chunk.len() as u64;

        // Emit progress event
        if total_size > 0 {
            let progress = (downloaded as f64 / total_size as f64 * 100.0) as u32;
            app.emit("download-progress-evebox", progress).ok();
        }
    }

    // Ensure file is flushed and closed
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|e| e.to_string())?;
    drop(file);

    // Clean up any existing temp extract directory
    let _ = std::fs::remove_dir_all(&temp_extract_dir);

    // Extract the zip file to temp directory
    let temp_zip_str = temp_zip_path.to_str().ok_or("Invalid zip path")?;
    let temp_extract_str = temp_extract_dir.to_str().ok_or("Invalid extract path")?;

    let extract_command = format!(
        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
        temp_zip_str, temp_extract_str
    );

    let output = Command::new("powershell")
        .args(&["-Command", &extract_command])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Failed to extract zip: {}", e))?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to extract EveBox: {}", error));
    }

    // Find evebox.exe in the extracted files
    let find_command = format!(
        "Get-ChildItem -Path '{}' -Filter 'evebox.exe' -Recurse | Select-Object -First 1 -ExpandProperty FullName",
        temp_extract_str
    );

    let find_output = Command::new("powershell")
        .args(&["-Command", &find_command])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Failed to find evebox.exe: {}", e))?;

    if !find_output.status.success() {
        return Err("Failed to find evebox.exe in extracted files".to_string());
    }

    let evebox_source = String::from_utf8_lossy(&find_output.stdout)
        .trim()
        .to_string();
    if evebox_source.is_empty() {
        return Err("evebox.exe not found in the zip file".to_string());
    }

    // Copy evebox.exe to bin directory
    let evebox_dest = std::path::Path::new(&evebox_bin_dir).join("evebox.exe");
    let copy_command = format!(
        "Copy-Item -Path '{}' -Destination '{}' -Force",
        evebox_source,
        evebox_dest.to_str().ok_or("Invalid destination path")?
    );

    let copy_output = Command::new("powershell")
        .args(&["-Command", &copy_command])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Failed to copy evebox.exe: {}", e))?;

    if !copy_output.status.success() {
        let error = String::from_utf8_lossy(&copy_output.stderr);
        return Err(format!("Failed to copy evebox.exe: {}", error));
    }

    // Clean up temporary files
    let _ = std::fs::remove_file(&temp_zip_path);
    let _ = std::fs::remove_dir_all(&temp_extract_dir);

    // Verify evebox.exe exists in bin directory
    if evebox_dest.exists() {
        Ok(format!(
            "EveBox installed successfully to: {}",
            evebox_dest.display()
        ))
    } else {
        Err("Failed to install evebox.exe to bin directory".to_string())
    }
}

#[tauri::command]
fn check_suricata_status() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        // Check if Suricata process is running
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "(Get-Process suricata -ErrorAction SilentlyContinue) -ne $null",
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("Failed to check Suricata status: {}", e))?;

        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout);
            Ok(result.trim() == "True")
        } else {
            Ok(false)
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Suricata control is only available on Windows".to_string())
    }
}

#[tauri::command]
async fn start_suricata_with_output(
    app: AppHandle,
    suricata_process: State<'_, Mutex<SuricataProcess>>,
    selected_interface: String,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // Stop any existing process
        {
            let child = if let Ok(mut process_guard) = suricata_process.lock() {
                process_guard.handle.take()
            } else {
                None
            };
            if let Some(mut child) = child {
                let _ = child.kill().await;
            }
        }

        // Extract GUID from the selected interface string
        let interface_guid = if let Some(guid_start) = selected_interface.find('{') {
            if let Some(guid_end) = selected_interface.find('}') {
                format!(
                    r"\Device\NPF_{}",
                    &selected_interface[guid_start..=guid_end]
                )
            } else {
                return Err("Invalid interface format: missing closing brace for GUID".to_string());
            }
        } else {
            return Err("Invalid interface format: no GUID found".to_string());
        };

        let suricata_dir = r"C:\Program Files\Suricata";
        // Get user's home directory for log files
        let log_dir = std::env::var("USERPROFILE")
            .map(|home| format!(r"{}\.meerkat-desktop\log", home))
            .unwrap_or_else(|_| r"C:\suricata\log".to_string());
        let _ = std::fs::create_dir_all(&log_dir);

        // Get rules path
        let rules_path = std::env::var("USERPROFILE")
            .map(|home| format!(r"{}\.meerkat-desktop\rules\suricata.rules", home))
            .unwrap_or_else(|_| r"C:\suricata\rules\suricata.rules".to_string());

        // Ensure threshold.conf exists
        let threshold_path = std::env::var("USERPROFILE")
            .map(|home| format!(r"{}\.meerkat-desktop\threshold.conf", home))
            .unwrap_or_else(|_| r"C:\suricata\threshold.conf".to_string());

        // Create threshold.conf if it doesn't exist
        if !std::path::Path::new(&threshold_path).exists() {
            let _ = app.emit(
                "suricata-output",
                serde_json::json!({
                    "type": "info",
                    "line": format!("Creating threshold.conf at {}", threshold_path)
                }),
            );
            // Create the directory if it doesn't exist
            if let Some(parent) = std::path::Path::new(&threshold_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // Create an empty threshold.conf file
            std::fs::write(
                &threshold_path,
                "# Threshold config file\n# Add threshold rules here\n",
            )
            .map_err(|e| format!("Failed to create threshold.conf: {}", e))?;
        }

        // Build the command
        let suricata_command = format!(
            r"cd '{}'; .\suricata.exe -v -i '{}' -c .\suricata.yaml -l '{}' -S '{}' --set threshold-file='{}'",
            suricata_dir, interface_guid, log_dir, rules_path, threshold_path
        );

        // Emit the command to the output terminal
        let _ = app.emit(
            "suricata-output",
            serde_json::json!({
                "type": "info",
                "line": format!("Starting Suricata with command:")
            }),
        );
        let _ = app.emit(
            "suricata-output",
            serde_json::json!({
                "type": "info",
                "line": format!(">>> {}", suricata_command)
            }),
        );
        let _ = app.emit(
            "suricata-output",
            serde_json::json!({
                "type": "info",
                "line": "---"
            }),
        );

        // Only run non-admin version
        let mut cmd = TokioCommand::new("powershell");
        cmd.args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &suricata_command,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start Suricata: {}", e))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        {
            if let Ok(mut process_guard) = suricata_process.lock() {
                process_guard.handle = Some(child);
            }
        }
        if let Some(stdout) = stdout {
            let app_clone = app.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = app_clone.emit(
                        "suricata-output",
                        serde_json::json!({
                            "type": "stdout",
                            "line": line
                        }),
                    );
                }
            });
        }
        if let Some(stderr) = stderr {
            let app_clone = app.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = app_clone.emit(
                        "suricata-output",
                        serde_json::json!({
                            "type": "stderr",
                            "line": line
                        }),
                    );
                }
            });
        }
        let _ = app.emit(
            "suricata-output",
            serde_json::json!({
                "type": "info",
                "line": format!("Suricata log directory: {}", log_dir)
            }),
        );
        Ok("Suricata started with output streaming".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Suricata control is only available on Windows".to_string())
    }
}

#[tauri::command]
async fn stop_suricata_with_output(
    app: AppHandle,
    suricata_process: State<'_, Mutex<SuricataProcess>>,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // First try to stop the managed process handle
        {
            let child_to_kill = {
                if let Ok(mut process_guard) = suricata_process.lock() {
                    // First emit a message that we're stopping
                    app.emit(
                        "suricata-output",
                        serde_json::json!({
                            "type": "stdout",
                            "line": "Stopping managed Suricata process..."
                        }),
                    )
                    .ok();

                    // Take the child process out of the mutex
                    process_guard.handle.take()
                } else {
                    None
                }
            }; // Drop the mutex guard here

            if let Some(mut child) = child_to_kill {
                // Try to kill the child process gracefully
                let _ = child.kill().await;

                app.emit(
                    "suricata-output",
                    serde_json::json!({
                        "type": "stdout",
                        "line": "Managed process terminated"
                    }),
                )
                .ok();
            }
        }

        // Now check for any remaining Suricata processes
        app.emit(
            "suricata-output",
            serde_json::json!({
                "type": "stdout",
                "line": "Checking for any other Suricata processes..."
            }),
        )
        .ok();

        // Try multiple methods to stop Suricata
        let ps_script = r#"
                # Find ALL Suricata processes
                $allSuricataProcesses = Get-Process suricata -ErrorAction SilentlyContinue
                
                if ($allSuricataProcesses) {
                    Write-Host "Found $($allSuricataProcesses.Count) Suricata process(es) to stop"
                    
                    $processesToStop = $allSuricataProcesses
                    
                    foreach ($process in $processesToStop) {
                        Write-Host "Stopping Suricata process (PID: $($process.Id))"
                        
                        # Method 1: Try WM_CLOSE to any windows
                        try {
                            if ($process.MainWindowHandle -ne 0) {
                                Add-Type @"
                                using System;
                                using System.Runtime.InteropServices;
                                public class Win32Window {
                                    [DllImport("user32.dll")]
                                    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
                                    public const uint WM_CLOSE = 0x0010;
                                }
"@
                                [Win32Window]::SendMessage($process.MainWindowHandle, [Win32Window]::WM_CLOSE, 0, 0)
                                Write-Host "Sent WM_CLOSE to main window"
                            }
                        } catch {
                            # Window close failed, continue
                        }
                        
                        # Method 2: Use taskkill with /F flag to force terminate immediately
                        Write-Host "Force terminating Suricata process..."
                        $taskKillResult = & taskkill /PID $process.Id /F 2>&1
                        Write-Host "Taskkill result: $taskKillResult"
                        
                        # Give it a moment to terminate
                        Start-Sleep -Milliseconds 500
                        
                        # Final check and use Stop-Process if needed
                        $finalCheck = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
                        if ($finalCheck) {
                            Write-Host "Process still running, using Stop-Process..."
                            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                        }
                        
                        Write-Host "Process $($process.Id) has been stopped"
                    }
                    
                    # Final verification - check if any Suricata processes remain
                    Start-Sleep -Milliseconds 500
                    $remaining = Get-Process suricata -ErrorAction SilentlyContinue
                    if ($remaining) {
                        Write-Host "Warning: Some Suricata processes may still be running"
                        foreach ($proc in $remaining) {
                            Write-Host "  - PID: $($proc.Id)"
                        }
                    } else {
                        Write-Host "All Suricata processes have been successfully stopped"
                    }
                } else {
                    Write-Host "No Suricata processes found to stop"
                }
                "#;

        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &ps_script,
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("Failed to stop Suricata: {}", e))?;

        // Emit PowerShell output
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if !line.trim().is_empty() {
                app.emit(
                    "suricata-output",
                    serde_json::json!({
                        "type": "stdout",
                        "line": line
                    }),
                )
                .ok();
            }
        }

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            app.emit(
                "suricata-output",
                serde_json::json!({
                    "type": "stderr",
                    "line": format!("Error stopping Suricata: {}", error)
                }),
            )
            .ok();
        }

        // Clean up the process handle
        {
            if let Ok(mut process_guard) = suricata_process.lock() {
                process_guard.handle = None;
            }
        }

        // Give it a moment for final output
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Emit confirmation message
        app.emit(
            "suricata-output",
            serde_json::json!({
                "type": "stdout",
                "line": "✓ Suricata has been stopped successfully"
            }),
        )
        .ok();

        Ok("Suricata stopped successfully".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Suricata control is only available on Windows".to_string())
    }
}

#[tauri::command]
async fn start_eve_json_tail(
    app: AppHandle,
    eve_json_tailer: State<'_, EveJsonTailer>,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // Set running flag
        {
            if let Ok(mut is_running) = eve_json_tailer.is_running.lock() {
                *is_running = true;
            }
        }

        // Get log directory
        let log_dir = std::env::var("USERPROFILE")
            .map(|home| format!(r"{}\.meerkat-desktop\log", home))
            .unwrap_or_else(|_| r"C:\suricata\log".to_string());
        let eve_path = format!(r"{}\eve.json", log_dir);

        // Spawn task to tail the file
        let is_running = eve_json_tailer.is_running.clone();
        let app_clone = app.clone();
        tokio::spawn(async move {
            let mut last_position = 0u64;

            loop {
                // Check if we should stop
                {
                    if let Ok(running) = is_running.lock() {
                        if !*running {
                            break;
                        }
                    }
                }

                // Try to open and read the file
                if let Ok(mut file) = File::open(&eve_path).await {
                    if let Ok(metadata) = file.metadata().await {
                        let current_size = metadata.len();

                        if current_size > last_position {
                            // Seek to last position
                            use tokio::io::AsyncSeekExt;
                            if let Ok(_) = file.seek(std::io::SeekFrom::Start(last_position)).await
                            {
                                let reader = BufReader::new(file);
                                let mut lines = reader.lines();

                                while let Ok(Some(line)) = lines.next_line().await {
                                    // Parse JSON and emit event
                                    if let Ok(json) =
                                        serde_json::from_str::<serde_json::Value>(&line)
                                    {
                                        let _ = app_clone.emit("eve-json-event", json);
                                    }
                                }
                            }

                            last_position = current_size;
                        }
                    }
                }

                // Sleep for a bit before checking again
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        });

        Ok("Started tailing eve.json".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Eve.json tailing is only available on Windows".to_string())
    }
}

#[tauri::command]
async fn stop_eve_json_tail(eve_json_tailer: State<'_, EveJsonTailer>) -> Result<String, String> {
    // Set running flag to false
    if let Ok(mut is_running) = eve_json_tailer.is_running.lock() {
        *is_running = false;
    }

    Ok("Stopped tailing eve.json".to_string())
}

#[tauri::command]
async fn update_rules(app: AppHandle) -> Result<String, String> {
    // Define rule sources
    struct RuleSource {
        url: &'static str,
        is_archive: bool,
    }

    let sources = vec![
        RuleSource {
            url: "https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz",
            is_archive: true,
        },
        RuleSource {
            url: "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules",
            is_archive: false,
        },
        RuleSource {
            url: "https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz",
            is_archive: true,
        },
    ];

    // Get user's home directory for rules
    let rules_dir = std::env::var("USERPROFILE")
        .map(|home| format!(r"{}\.meerkat-desktop\rules", home))
        .unwrap_or_else(|_| r"C:\suricata\rules".to_string());

    // Create rules directory if it doesn't exist
    std::fs::create_dir_all(&rules_dir)
        .map_err(|e| format!("Failed to create rules directory: {}", e))?;

    // Start with empty rules
    let mut all_rules = String::new();
    let mut total_rule_files = 0;

    // Process each source
    for (index, source) in sources.iter().enumerate() {
        let _ = app.emit(
            "rules-update-progress",
            serde_json::json!({
                "type": "info",
                "message": format!("Downloading from: {}", source.url),
                "url": source.url,
                "current_source": index + 1,
                "total_sources": sources.len()
            }),
        );

        let response = reqwest::get(source.url).await.map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!(
                "Failed to download from {}: HTTP {}",
                source.url,
                response.status()
            ));
        }

        // Get content length for progress tracking
        let total_size = response.content_length().unwrap_or(0);

        if source.is_archive {
            // Handle tar.gz files
            let temp_path = format!("{}/temp_{}.tar.gz", rules_dir, index);
            let mut file = tokio::fs::File::create(&temp_path)
                .await
                .map_err(|e| e.to_string())?;

            // Stream download with progress
            let mut stream = response.bytes_stream();
            let mut downloaded = 0u64;

            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| e.to_string())?;
                tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                    .await
                    .map_err(|e| e.to_string())?;
                downloaded += chunk.len() as u64;

                // Emit progress
                if total_size > 0 {
                    let progress = (downloaded as f64 / total_size as f64 * 100.0) as u32;
                    let _ = app.emit(
                        "rules-update-progress",
                        serde_json::json!({
                            "type": "download",
                            "progress": progress,
                            "downloaded": downloaded,
                            "total": total_size,
                            "url": source.url
                        }),
                    );
                }
            }

            // Ensure file is flushed
            tokio::io::AsyncWriteExt::flush(&mut file)
                .await
                .map_err(|e| e.to_string())?;
            drop(file);

            let _ = app.emit(
                "rules-update-progress",
                serde_json::json!({
                    "type": "info",
                    "message": format!("Extracting rules from: {}", source.url)
                }),
            );

            // Extract the tar.gz file
            let tar_gz = std::fs::File::open(&temp_path).map_err(|e| e.to_string())?;
            let tar = GzDecoder::new(tar_gz);
            let mut archive = Archive::new(tar);

            // Extract to temporary directory
            let temp_extract_dir = format!("{}/temp_extract_{}", rules_dir, index);
            std::fs::create_dir_all(&temp_extract_dir).map_err(|e| e.to_string())?;

            archive
                .unpack(&temp_extract_dir)
                .map_err(|e| format!("Failed to extract archive: {}", e))?;

            // Process extracted files
            let mut rule_count = 0;
            let mut support_file_count = 0;

            fn process_extracted_files(
                src_dir: &Path,
                rules_dir: &Path,
                all_rules: &mut String,
                rule_count: &mut i32,
                support_file_count: &mut i32,
            ) -> std::io::Result<()> {
                if src_dir.is_dir() {
                    for entry in std::fs::read_dir(src_dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        if path.is_dir() {
                            process_extracted_files(
                                &path,
                                rules_dir,
                                all_rules,
                                rule_count,
                                support_file_count,
                            )?;
                        } else if path.extension().and_then(|s| s.to_str()) == Some("rules") {
                            // Read and concatenate .rules files
                            let content = std::fs::read_to_string(&path)?;
                            all_rules.push_str(&content);
                            all_rules.push('\n');
                            *rule_count += 1;
                        } else if let Some(file_name) = path.file_name() {
                            // Copy non-.rules files to the rules directory
                            let dest_path = rules_dir.join(file_name);
                            std::fs::copy(&path, &dest_path)?;
                            *support_file_count += 1;
                        }
                    }
                }
                Ok(())
            }

            process_extracted_files(
                Path::new(&temp_extract_dir),
                Path::new(&rules_dir),
                &mut all_rules,
                &mut rule_count,
                &mut support_file_count,
            )
            .map_err(|e| format!("Failed to process extracted files: {}", e))?;

            total_rule_files += rule_count;

            if support_file_count > 0 {
                let _ = app.emit("rules-update-progress", serde_json::json!({
                    "type": "info",
                    "message": format!("Copied {} support files from: {}", support_file_count, source.url)
                }));
            }

            // Clean up temporary files
            let _ = std::fs::remove_file(&temp_path);
            let _ = std::fs::remove_dir_all(&temp_extract_dir);
        } else {
            // Handle direct .rules files
            let content = response.text().await.map_err(|e| e.to_string())?;
            all_rules.push_str(&content);
            all_rules.push('\n');
            total_rule_files += 1;

            let _ = app.emit(
                "rules-update-progress",
                serde_json::json!({
                    "type": "info",
                    "message": format!("Downloaded rules from: {}", source.url)
                }),
            );
        }
    }

    // Write concatenated rules to suricata.rules
    let suricata_rules_path = format!("{}/suricata.rules", rules_dir);
    std::fs::write(&suricata_rules_path, &all_rules)
        .map_err(|e| format!("Failed to write suricata.rules: {}", e))?;

    let _ = app.emit("rules-update-progress", serde_json::json!({
        "type": "complete",
        "message": format!("Rules updated successfully! Processed {} rule files from {} sources.", total_rule_files, sources.len())
    }));

    Ok(format!(
        "Rules updated successfully! {} rule files concatenated into {}",
        total_rule_files, suricata_rules_path
    ))
}

#[tauri::command]
async fn start_evebox_with_output(
    app: AppHandle,
    evebox_process: State<'_, Mutex<EveBoxProcess>>,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // Stop any existing process
        {
            let child = if let Ok(mut process_guard) = evebox_process.lock() {
                process_guard.handle.take()
            } else {
                None
            };
            if let Some(mut child) = child {
                let _ = child.kill().await;
            }
        }

        // Get evebox location from .meerkat-desktop directory
        let evebox_path = std::env::var("USERPROFILE")
            .map(|home| format!(r"{}\.meerkat-desktop\evebox\bin\evebox.exe", home))
            .map_err(|_| "Could not find user profile directory".to_string())?;

        if !std::path::Path::new(&evebox_path).exists() {
            return Err(format!(
                "EveBox not found at: {}. Please install EveBox first.",
                evebox_path
            ));
        }

        // Get user's home directory for log files
        let eve_json_path = std::env::var("USERPROFILE")
            .map(|home| format!(r"{}\.meerkat-desktop\log\eve.json", home))
            .unwrap_or_else(|_| r"C:\suricata\log\eve.json".to_string());

        // Get evebox data directory
        let evebox_data_dir = std::env::var("USERPROFILE")
            .map(|home| format!(r"{}\.meerkat-desktop\evebox", home))
            .map_err(|_| "Could not find user profile directory".to_string())?;

        // Emit the command to the output terminal
        let _ = app.emit(
            "evebox-output",
            serde_json::json!({
                "type": "info",
                "line": format!("Starting EveBox with command:")
            }),
        );
        let _ = app.emit(
            "evebox-output",
            serde_json::json!({
                "type": "info",
                "line": format!(">>> {} -D {} server --no-tls --no-auth --database sqlite {}",
                    evebox_path, evebox_data_dir, eve_json_path)
            }),
        );
        let _ = app.emit(
            "evebox-output",
            serde_json::json!({
                "type": "info",
                "line": "---"
            }),
        );
        let _ = app.emit(
            "evebox-output",
            serde_json::json!({
                "type": "info",
                "line": "EveBox will be available at http://localhost:5636"
            }),
        );
        let _ = app.emit(
            "evebox-output",
            serde_json::json!({
                "type": "info",
                "line": "---"
            }),
        );

        // Execute EveBox directly without cmd wrapper
        let mut cmd = TokioCommand::new(&evebox_path);
        cmd.args(&[
            "-D",
            &evebox_data_dir,
            "server",
            "--no-tls",
            "--no-auth",
            "--database",
            "sqlite",
            &eve_json_path,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start EveBox: {}", e))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        {
            if let Ok(mut process_guard) = evebox_process.lock() {
                process_guard.handle = Some(child);
            }
        }

        if let Some(stdout) = stdout {
            let app_clone = app.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let cleaned_line = strip_ansi_codes(&line);
                    let _ = app_clone.emit(
                        "evebox-output",
                        serde_json::json!({
                            "type": "stdout",
                            "line": cleaned_line
                        }),
                    );
                }
            });
        }

        if let Some(stderr) = stderr {
            let app_clone = app.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let cleaned_line = strip_ansi_codes(&line);
                    let _ = app_clone.emit(
                        "evebox-output",
                        serde_json::json!({
                            "type": "stderr",
                            "line": cleaned_line
                        }),
                    );
                }
            });
        }

        Ok("EveBox started with output streaming".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("EveBox control is only available on Windows".to_string())
    }
}

#[tauri::command]
async fn stop_evebox_with_output(
    app: AppHandle,
    evebox_process: State<'_, Mutex<EveBoxProcess>>,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // Stop the process if we have a handle
        let child = if let Ok(mut process_guard) = evebox_process.lock() {
            process_guard.handle.take()
        } else {
            None
        };

        if let Some(mut child) = child {
            let _ = child.kill().await;
        }

        // Also force kill any remaining EveBox processes
        let output = Command::new("taskkill")
            .args(&["/IM", "evebox.exe", "/F"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("Failed to execute taskkill: {}", e))?;

        let result = if output.status.success() {
            "EveBox stopped successfully"
        } else {
            "EveBox stop command completed (process may not have been running)"
        };

        let _ = app.emit(
            "evebox-output",
            serde_json::json!({
                "type": "info",
                "line": result
            }),
        );

        Ok(result.to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("EveBox control is only available on Windows".to_string())
    }
}

#[tauri::command]
fn check_evebox_status() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        // Check if EveBox process is running
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "(Get-Process evebox -ErrorAction SilentlyContinue) -ne $null",
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("Failed to check EveBox status: {}", e))?;

        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout);
            Ok(result.trim() == "True")
        } else {
            Ok(false)
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("EveBox control is only available on Windows".to_string())
    }
}

#[tauri::command]
fn open_evebox_url() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // Open URL in default browser using Windows 'start' command
        Command::new("cmd")
            .args(&["/c", "start", "http://localhost:5636"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
            .map_err(|e| format!("Failed to open EveBox URL: {}", e))?;

        Ok("EveBox URL opened in browser".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("This command is only available on Windows".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Mutex::new(SuricataProcess { handle: None }))
        .manage(Mutex::new(EveBoxProcess { handle: None }))
        .manage(EveJsonTailer {
            is_running: Arc::new(Mutex::new(false)),
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            get_network_interfaces,
            install_suricata,
            install_npcap,
            install_evebox,
            check_suricata_status,
            start_suricata_with_output,
            stop_suricata_with_output,
            check_evebox_status,
            start_evebox_with_output,
            stop_evebox_with_output,
            open_evebox_url,
            start_eve_json_tail,
            stop_eve_json_tail,
            update_rules
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // Kill Suricata and EveBox processes when window is closing
                #[cfg(target_os = "windows")]
                {
                    // Force kill all Suricata processes
                    let _ = Command::new("taskkill")
                        .args(&["/IM", "suricata.exe", "/F"])
                        .creation_flags(0x08000000) // CREATE_NO_WINDOW
                        .output();

                    // Force kill all EveBox processes
                    let _ = Command::new("taskkill")
                        .args(&["/IM", "evebox.exe", "/F"])
                        .creation_flags(0x08000000) // CREATE_NO_WINDOW
                        .output();
                }
                // Allow the window to close
                window.close().unwrap();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
