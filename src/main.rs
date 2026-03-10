//! RAS Remover v2.0.0 — утилита для полного удаления популярных Remote Access Software
//!
//! Поддерживаемые инструменты (15 штук):
//!   1. AnyDesk
//!   2. TeamViewer
//!   3. Chrome Remote Desktop
//!   4. Splashtop
//!   5. LogMeIn
//!   6. ConnectWise Control (ScreenConnect)
//!   7. RealVNC / VNC Connect
//!   8. TightVNC
//!   9. UltraVNC
//!   10. Ammyy Admin
//!   11. Supremo
//!   12. RemotePC
//!   13. GoToMyPC / GoTo Resolve
//!   14. Zoho Assist
//!   15. Radmin
//!
//! Запуск: ras_remover.exe [--silent] [--dry-run] [--log-dir C:\Logs] [--tool "AnyDesk"]

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use chrono::Local;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

// ===========================================================================
// Windows API — скрытие консольного окна
// ===========================================================================

#[cfg(windows)]
fn hide_console_window() {
    extern "system" {
        fn GetConsoleWindow() -> isize;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn FreeConsole() -> i32;
    }
    const SW_HIDE: i32 = 0;
    unsafe {
        let window = GetConsoleWindow();
        if window != 0 {
            ShowWindow(window, SW_HIDE);
        }
        FreeConsole();
    }
}

#[cfg(not(windows))]
fn hide_console_window() {}

// ===========================================================================
// Проверка прав администратора
// ===========================================================================

#[cfg(windows)]
fn is_admin() -> bool {
    extern "system" {
        fn GetLastError() -> u32;
    }
    extern "system" {
        fn OpenProcessToken(
            process_handle: *mut std::ffi::c_void,
            desired_access: u32,
            token_handle: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn GetTokenInformation(
            token_handle: *mut std::ffi::c_void,
            token_information_class: u32,
            token_information: *mut std::ffi::c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn CloseHandle(h_object: *mut std::ffi::c_void) -> i32;
    }

    const TOKEN_QUERY: u32 = 0x00000008;
    const TOKEN_ELEVATION: u32 = 20;

    unsafe {
        let mut token_handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let h_process = GetCurrentProcess();

        if OpenProcessToken(h_process, TOKEN_QUERY, &mut token_handle) == 0 {
            return false;
        }

        let mut elevation: u32 = 0;
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TOKEN_ELEVATION,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut return_length,
        );

        CloseHandle(token_handle);

        result != 0 && elevation != 0
    }
}

#[cfg(not(windows))]
fn is_admin() -> bool {
    true
}

// ===========================================================================
// Логгер
// ===========================================================================

struct FileLogger {
    file: std::fs::File,
}

impl FileLogger {
    fn new(log_dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(log_dir)?;
        let hostname = env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("ras_remover_{}_{}.log", hostname, timestamp);
        let path = log_dir.join(filename);
        let file = fs::File::create(&path)?;
        let mut logger = FileLogger { file };
        logger.info(&format!("Лог создан: {}", path.display()));
        logger.info(&format!("Хост: {}", hostname));
        logger.info(&format!(
            "Пользователь: {}",
            env::var("USERNAME").unwrap_or_else(|_| "SYSTEM".into())
        ));
        logger.info("=".repeat(60).as_str());
        Ok(logger)
    }

    fn log(&mut self, level: &str, msg: &str) {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let line = format!("[{}] [{}] {}\n", ts, level, msg);
        print!("{}", line);
        let _ = self.file.write_all(line.as_bytes());
        let _ = self.file.flush();
    }

    fn info(&mut self, msg: &str) {
        self.log("INFO ", msg);
    }
    fn warn(&mut self, msg: &str) {
        self.log("WARN ", msg);
    }
    fn error(&mut self, msg: &str) {
        self.log("ERROR", msg);
    }
    fn ok(&mut self, msg: &str) {
        self.log(" OK  ", msg);
    }
}

// ===========================================================================
// Конфиг
// ===========================================================================

#[derive(Clone)]
struct Config {
    dry_run: bool,
    silent: bool,
    log_dir: PathBuf,
    target_tool: Option<String>,
}

impl Config {
    fn from_args() -> Self {
        let args: Vec<String> = env::args().collect();
        let dry_run = args.iter().any(|a| a == "--dry-run");
        let silent = args.iter().any(|a| a == "--silent");

        let log_dir = args
            .iter()
            .position(|a| a == "--log-dir")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\RASRemover\Logs"));

        let target_tool = args
            .iter()
            .position(|a| a == "--tool")
            .and_then(|i| args.get(i + 1))
            .cloned();

        Config {
            dry_run,
            silent,
            log_dir,
            target_tool,
        }
    }
}

// ===========================================================================
// RAS Tool Descriptor
// ===========================================================================

#[derive(Debug, Clone)]
struct RasTool {
    name: &'static str,
    process_names: &'static [&'static str],
    service_names: &'static [&'static str],
    registry_display_names: &'static [&'static str],
    exe_filenames: &'static [&'static str],
    appdata_dirs: &'static [&'static str],
    firewall_rule_names: &'static [&'static str],
    silent_args: &'static [&'static str],
}

// ===========================================================================
// Detection & Removal Results
// ===========================================================================

#[derive(Debug, Default)]
struct ToolDetectionResult {
    tool: Option<&'static RasTool>,
    found: bool,
    running_processes: Vec<(u32, PathBuf)>,
    install_dirs: Vec<PathBuf>,
    uninstall_strings: Vec<String>,
    registry_keys_to_delete: Vec<String>,
    data_dirs: Vec<PathBuf>,
    active_services: Vec<String>,
}

#[derive(Debug)]
struct UninstallerCommand {
    executable: PathBuf,
    args: Vec<String>,
}

#[derive(Debug, Default)]
struct RemovalSummary {
    tool_name: String,
    processes_killed: bool,
    uninstaller_ran: bool,
    uninstaller_exit_code: Option<i32>,
    services_deleted: Vec<String>,
    files_deleted: Vec<PathBuf>,
    files_failed: Vec<PathBuf>,
    registry_keys_deleted: Vec<String>,
    registry_keys_failed: Vec<String>,
    firewall_rules_cleaned: bool,
    final_verification_clean: bool,
}

#[derive(Debug, Clone)]
struct PortableFoundResult {
    tool_name: String,
    exe_path: PathBuf,
}

// ===========================================================================
// RAS Tools Table — 15 популярных инструментов удалённого доступа
// ===========================================================================

static RAS_TOOLS: &[RasTool] = &[
    // 1. AnyDesk
    RasTool {
        name: "AnyDesk",
        process_names: &["anydesk.exe"],
        service_names: &["AnyDesk"],
        registry_display_names: &["anydesk"],
        exe_filenames: &["AnyDesk.exe"],
        appdata_dirs: &["AnyDesk"],
        firewall_rule_names: &["AnyDesk"],
        silent_args: &["--remove", "--silent"],
    },
    // 2. TeamViewer
    RasTool {
        name: "TeamViewer",
        process_names: &["teamviewer.exe", "tv_w32.exe", "tv_x64.exe", "teamviewer_service.exe"],
        service_names: &["TeamViewer", "TeamViewer14", "TeamViewer15"],
        registry_display_names: &["teamviewer"],
        exe_filenames: &["TeamViewer.exe"],
        appdata_dirs: &["TeamViewer"],
        firewall_rule_names: &["TeamViewer"],
        silent_args: &["/S"],
    },
    // 3. Chrome Remote Desktop
    RasTool {
        name: "Chrome Remote Desktop",
        process_names: &["remoting_host.exe", "remoting_start_host.exe", "chrome_remote_desktop_host.exe"],
        service_names: &["chromoting", "Chrome Remote Desktop Host"],
        registry_display_names: &["chrome remote desktop"],
        exe_filenames: &["remoting_host.exe"],
        appdata_dirs: &["Google\\Chrome Remote Desktop"],
        firewall_rule_names: &["Chrome Remote Desktop", "chromoting"],
        silent_args: &["/S"],
    },
    // 4. Splashtop
    RasTool {
        name: "Splashtop",
        process_names: &["sragent.exe", "srmanager.exe", "srfeature.exe", "splashtopstreamer.exe", "strwinclt.exe"],
        service_names: &["SplashtopRemoteService", "SRService"],
        registry_display_names: &["splashtop"],
        exe_filenames: &["SplashtopStreamer.exe", "SRAgent.exe"],
        appdata_dirs: &["Splashtop", "Splashtop Remote"],
        firewall_rule_names: &["Splashtop"],
        silent_args: &["/S", "/VERYSILENT"],
    },
    // 5. LogMeIn
    RasTool {
        name: "LogMeIn",
        process_names: &["logmein.exe", "lmirescue.exe", "ramaint.exe", "logmeinrescue.exe", "lmiguardiansvc.exe"],
        service_names: &["LogMeIn", "LMIGuardianSvc", "LMIInfo"],
        registry_display_names: &["logmein"],
        exe_filenames: &["LogMeIn.exe"],
        appdata_dirs: &["LogMeIn"],
        firewall_rule_names: &["LogMeIn"],
        silent_args: &["/S"],
    },
    // 6. ConnectWise Control (ScreenConnect)
    RasTool {
        name: "ConnectWise Control",
        process_names: &["screenconnect.clientservice.exe", "connectwiseclient.exe", "screenconnect.windowsclient.exe"],
        service_names: &["ScreenConnect Client", "ConnectWiseControl"],
        registry_display_names: &["screenconnect", "connectwise control"],
        exe_filenames: &["ScreenConnect.ClientService.exe"],
        appdata_dirs: &["ScreenConnect Client", "ConnectWise Control"],
        firewall_rule_names: &["ScreenConnect", "ConnectWise Control"],
        silent_args: &["/S", "/quiet"],
    },
    // 7. RealVNC / VNC Connect
    RasTool {
        name: "RealVNC",
        process_names: &["vncserver.exe", "vncviewer.exe", "vnclicensewiz.exe", "vncserverui.exe"],
        service_names: &["vncserver", "VNC Server"],
        registry_display_names: &["realvnc", "vnc connect", "vnc server"],
        exe_filenames: &["vncserver.exe", "vncviewer.exe"],
        appdata_dirs: &["RealVNC"],
        firewall_rule_names: &["RealVNC", "VNC Server"],
        silent_args: &["/S", "/quiet"],
    },
    // 8. TightVNC
    RasTool {
        name: "TightVNC",
        process_names: &["tvnserver.exe", "tvnviewer.exe"],
        service_names: &["tvnserver", "TightVNC Server"],
        registry_display_names: &["tightvnc"],
        exe_filenames: &["tvnserver.exe", "tvnviewer.exe"],
        appdata_dirs: &["TightVNC"],
        firewall_rule_names: &["TightVNC"],
        silent_args: &["/S"],
    },
    // 9. UltraVNC
    RasTool {
        name: "UltraVNC",
        process_names: &["winvnc.exe", "uvnc_service.exe", "vncviewer.exe"],
        service_names: &["uvnc_service", "UltraVNC"],
        registry_display_names: &["ultravnc"],
        exe_filenames: &["WinVNC.exe", "uvnc_service.exe"],
        appdata_dirs: &["uvnc"],
        firewall_rule_names: &["UltraVNC"],
        silent_args: &["/S"],
    },
    // 10. Ammyy Admin
    RasTool {
        name: "Ammyy Admin",
        process_names: &["aa_v3.exe", "ammyy_admin.exe"],
        service_names: &["AmmyyAdmin", "Ammyy"],
        registry_display_names: &["ammyy"],
        exe_filenames: &["AA_v3.exe"],
        appdata_dirs: &["Ammyy Admin", "Ammyy"],
        firewall_rule_names: &["Ammyy"],
        silent_args: &["/S"],
    },
    // 11. Supremo
    RasTool {
        name: "Supremo",
        process_names: &["supremo.exe", "supremoservice.exe", "supremoreporter.exe"],
        service_names: &["SupremoService"],
        registry_display_names: &["supremo"],
        exe_filenames: &["Supremo.exe"],
        appdata_dirs: &["Supremo", "Nanosystems\\Supremo"],
        firewall_rule_names: &["Supremo"],
        silent_args: &["/S"],
    },
    // 12. RemotePC
    RasTool {
        name: "RemotePC",
        process_names: &["remotepc.exe", "rpcsuite.exe", "remotepcservice.exe"],
        service_names: &["RemotePCService", "RPCService"],
        registry_display_names: &["remotepc"],
        exe_filenames: &["RemotePC.exe"],
        appdata_dirs: &["RemotePC"],
        firewall_rule_names: &["RemotePC"],
        silent_args: &["/S", "/quiet"],
    },
    // 13. GoToMyPC / GoTo Resolve
    RasTool {
        name: "GoToMyPC",
        process_names: &["g2mstart.exe", "g2mlauncher.exe", "gotomypc.exe", "g2m.exe", "gotoresolve.exe"],
        service_names: &["GoToMyPC", "GoTo Resolve", "g2mservice"],
        registry_display_names: &["gotomypc", "goto resolve", "goto opener"],
        exe_filenames: &["G2MLauncher.exe", "GoToMyPC.exe"],
        appdata_dirs: &["GoTo", "GoToMyPC", "Citrix Online"],
        firewall_rule_names: &["GoToMyPC", "GoTo Resolve"],
        silent_args: &["/S"],
    },
    // 14. Zoho Assist
    RasTool {
        name: "Zoho Assist",
        process_names: &["zohotray.exe", "zohounattended.exe", "zohoassist.exe", "zohors.exe"],
        service_names: &["ZohoAssistService", "ZohoUnattendedService"],
        registry_display_names: &["zoho assist"],
        exe_filenames: &["ZohoAssist.exe", "ZohoUnattended.exe"],
        appdata_dirs: &["Zoho Assist", "Zoho\\Assist"],
        firewall_rule_names: &["Zoho Assist"],
        silent_args: &["/S", "/quiet"],
    },
    // 15. Radmin
    RasTool {
        name: "Radmin",
        process_names: &["radmin.exe", "rserver3.exe", "rserverap.exe"],
        service_names: &["r_server", "Radmin Server"],
        registry_display_names: &["radmin", "famatech"],
        exe_filenames: &["Radmin.exe", "rserver3.exe"],
        appdata_dirs: &["Radmin", "Famatech"],
        firewall_rule_names: &["Radmin", "Famatech"],
        silent_args: &["/S", "/quiet"],
    },
];

// ===========================================================================
// Utility Functions
// ===========================================================================

/// Дедупликация путей (case-insensitive)
fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    paths
        .into_iter()
        .filter(|p| seen.insert(p.to_string_lossy().to_lowercase()))
        .collect()
}

/// Развернуть стандартные пути установки
fn expand_standard_paths(appdata_dirs: &[&str]) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let program_files = env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let program_files_x86 =
        env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
    let program_data = env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());

    for subdir in appdata_dirs {
        paths.push(PathBuf::from(format!(r"{}\{}", program_files, subdir)));
        paths.push(PathBuf::from(format!(r"{}\{}", program_files_x86, subdir)));
        paths.push(PathBuf::from(format!(r"{}\{}", program_data, subdir)));
    }

    paths
}

/// Собрать пути из профилей пользователей
fn collect_user_profile_paths(subdir: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(entries) = fs::read_dir(r"C:\Users") {
        for entry in entries.flatten() {
            let user_dir = entry.path();
            if user_dir.is_dir() {
                let user_name = user_dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                if ["Public", "Default", "Default User", "All Users"].contains(&user_name.as_str()) {
                    continue;
                }

                paths.push(user_dir.join(format!(r"AppData\Roaming\{}", subdir)));
                paths.push(user_dir.join(format!(r"AppData\Local\{}", subdir)));
            }
        }
    }

    paths
}

/// Парсинг UninstallString — главный фикс cmd /C бага
fn split_args(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in s.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    result.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

/// Распарсить UninstallString из реестра в executable + args
fn parse_uninstall_string(raw: &str) -> Option<UninstallerCommand> {
    let raw = raw.trim();

    let (exe_part, rest) = if raw.starts_with('"') {
        // Quoted path: "C:\path\tool.exe" --args
        let close = raw[1..].find('"')?;
        let exe = &raw[1..close + 1];
        let rest = raw[close + 2..].trim();
        (exe, rest)
    } else if raw.to_lowercase().starts_with("msiexec") {
        // MSI: msiexec.exe /X{GUID}
        let mut parts = raw.splitn(2, ' ');
        let exe = parts.next()?;
        let rest = parts.next().unwrap_or("").trim();
        (exe, rest)
    } else {
        // Unquoted: split on first space
        let mut parts = raw.splitn(2, ' ');
        let exe = parts.next()?;
        let rest = parts.next().unwrap_or("").trim();
        (exe, rest)
    };

    let executable = PathBuf::from(exe_part);
    if !executable.exists() {
        return None;
    }

    let args = split_args(rest);
    Some(UninstallerCommand { executable, args })
}

// ===========================================================================
// Registry Operations
// ===========================================================================

/// Запрос к реестру: поиск UninstallString + InstallLocation
fn query_registry_uninstall(
    display_name_keywords: &[&str],
    log: &mut FileLogger,
) -> Vec<(String, Option<String>, Option<PathBuf>)> {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut results = Vec::new();

    let search_roots: &[(&str, winreg::HKEY)] = &[
        ("HKLM", HKEY_LOCAL_MACHINE),
        ("HKCU", HKEY_CURRENT_USER),
    ];

    let uninstall_subkeys = &[
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    for (hive_name, hive) in search_roots {
        let root = RegKey::predef(*hive);
        for subkey_path in uninstall_subkeys {
            if let Ok(key) = root.open_subkey_with_flags(subkey_path, KEY_READ) {
                for name in key.enum_keys().filter_map(Result::ok) {
                    if let Ok(subkey) = key.open_subkey_with_flags(&name, KEY_READ) {
                        let display_name: String = subkey.get_value("DisplayName").unwrap_or_default();
                        let dn_lower = display_name.to_lowercase();

                        let matched = display_name_keywords.iter().any(|kw| dn_lower.contains(kw));

                        if matched {
                            let full_key = format!("{}\\{}\\{}", hive_name, subkey_path, name);
                            let uninstall: Option<String> = subkey.get_value("UninstallString").ok();
                            let install_loc: Option<PathBuf> = subkey
                                .get_value::<String, _>("InstallLocation")
                                .ok()
                                .map(PathBuf::from);

                            log.info(&format!(
                                "Найдена запись реестра: {} -> DisplayName=\"{}\"",
                                full_key, display_name
                            ));

                            results.push((full_key, uninstall, install_loc));
                        }
                    }
                }
            }
        }
    }

    results
}

// ===========================================================================
// Detection
// ===========================================================================

/// Поиск процессов по имени
fn find_running_processes(process_names: &[&str], sys: &System) -> Vec<(u32, PathBuf)> {
    let mut result = Vec::new();
    let process_names_lower: Vec<String> = process_names.iter().map(|s| s.to_lowercase()).collect();

    for proc in sys.processes().values() {
        let proc_name_lower = proc.name().to_lowercase();
        if process_names_lower.iter().any(|pn| proc_name_lower.contains(pn)) {
            if let Some(exe) = proc.exe() {
                result.push((proc.pid().as_u32(), exe.to_path_buf()));
            }
        }
    }

    result
}

/// Проверка существования сервиса
fn service_exists(service_name: &str) -> bool {
    if let Ok(output) = Command::new("sc").args(["query", service_name]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains(service_name) && !stdout.contains("1060")
    } else {
        false
    }
}

/// Разрешить пути установки из всех источников
fn resolve_install_dirs(
    process_paths: &[(u32, PathBuf)],
    registry_locations: &[PathBuf],
    appdata_dirs: &[&str],
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // 1. Из путей процессов
    for (_, exe_path) in process_paths {
        if let Some(parent) = exe_path.parent() {
            dirs.push(parent.to_path_buf());
        }
    }

    // 2. Из реестра
    for loc in registry_locations.iter() {
        dirs.push(loc.clone());
    }

    // 3. Стандартные пути
    dirs.extend(expand_standard_paths(appdata_dirs));

    // 4. Профили пользователей
    for subdir in appdata_dirs {
        dirs.extend(collect_user_profile_paths(subdir));
    }

    dedup_paths(dirs)
}

/// Сканирование одного инструмента
fn detect_tool(tool: &'static RasTool, sys: &System, log: &mut FileLogger) -> ToolDetectionResult {
    let mut result = ToolDetectionResult {
        tool: Some(tool),
        ..Default::default()
    };

    log.info(&format!("--- Сканирование: {} ---", tool.name));

    // 1. Процессы
    let running = find_running_processes(tool.process_names, sys);
    if !running.is_empty() {
        log.warn(&format!("Найдено {} процесс(ов):", running.len()));
        for (pid, path) in &running {
            log.warn(&format!("  PID={} Path={}", pid, path.display()));
        }
        result.found = true;
    }
    result.running_processes = running.clone();

    // 2. Реестр + UninstallString
    let registry_results = query_registry_uninstall(tool.registry_display_names, log);
    if !registry_results.is_empty() {
        result.found = true;
        for (key, uninstall, install_loc) in registry_results {
            result.registry_keys_to_delete.push(key);
            if let Some(u) = uninstall {
                result.uninstall_strings.push(u);
            }
            if let Some(loc) = install_loc {
                result.data_dirs.push(loc);
            }
        }
    }

    // 3. Сервисы
    for service in tool.service_names {
        if service_exists(service) {
            log.warn(&format!("Найдена служба: {}", service));
            result.found = true;
            result.active_services.push(service.to_string());
        }
    }

    // 4. Файлы — разрешить из всех источников
    let all_dirs = resolve_install_dirs(&running, &result.data_dirs, tool.appdata_dirs);
    result.install_dirs = dedup_paths(all_dirs);

    if result.found {
        log.warn(&format!("✓ {} обнаружен", tool.name));
    } else {
        log.info(&format!("✗ {} не найден", tool.name));
    }

    result
}

/// Сканирование всех инструментов
fn scan_all_tools(config: &Config, log: &mut FileLogger) -> Vec<ToolDetectionResult> {
    log.info("=== ФАЗА 1: СКАНИРОВАНИЕ ===");

    let sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );

    let mut detected = Vec::new();

    for tool in RAS_TOOLS {
        let should_scan = config
            .target_tool
            .as_ref()
            .map(|t| tool.name.to_lowercase().contains(&t.to_lowercase()))
            .unwrap_or(true);

        if should_scan {
            let result = detect_tool(tool, &sys, log);
            if result.found {
                detected.push(result);
            }
        }
    }

    detected
}

// ===========================================================================
// Removal
// ===========================================================================

/// Завершить процессы по имени
fn kill_processes_by_names(
    process_names: &[&str],
    dry_run: bool,
    log: &mut FileLogger,
) -> bool {
    log.info("Завершаем процессы...");

    if !dry_run {
        let _ = Command::new("sc").args(["stop", "AnyDesk"]).output();
        thread::sleep(Duration::from_secs(2));

        for proc_name in process_names {
            let _ = Command::new("taskkill")
                .args(["/F", "/IM", proc_name, "/T"])
                .output();
        }

        thread::sleep(Duration::from_secs(2));
    } else {
        log.info("[DRY-RUN] Завершение процессов");
    }

    log.ok("Процессы завершены");
    true
}

/// Запустить деинсталлятор — ПРАВИЛЬНО без cmd /C
fn run_uninstaller_command(
    cmd: &UninstallerCommand,
    silent_args: &[&str],
    dry_run: bool,
    log: &mut FileLogger,
) -> Option<i32> {
    let mut final_args = cmd.args.clone();
    for &sa in silent_args {
        if !final_args.iter().any(|a| a.eq_ignore_ascii_case(sa)) {
            final_args.push(sa.to_string());
        }
    }

    log.info(&format!("Запускаю деинсталлятор: {:?}", cmd.executable));

    if dry_run {
        log.info("[DRY-RUN] Пропускаю выполнение");
        return Some(0);
    }

    match Command::new(&cmd.executable).args(&final_args).output() {
        Ok(o) => {
            let code = o.status.code().unwrap_or(-1);
            if o.status.success() || code == 0 {
                log.ok(&format!("Деинсталлятор завершился (код {})", code));
            } else {
                log.warn(&format!(
                    "Деинсталлятор вернул код {}: {}",
                    code,
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Some(code)
        }
        Err(e) => {
            log.error(&format!("Ошибка запуска деинсталлятора: {}", e));
            None
        }
    }
}

/// Удалить сервисы
fn remove_services(
    service_names: &[&str],
    dry_run: bool,
    log: &mut FileLogger,
) -> Vec<String> {
    let mut deleted = Vec::new();

    for service in service_names {
        log.info(&format!("Удаляю службу: {}", service));

        if !dry_run {
            let _ = Command::new("sc").args(["stop", service]).output();
            thread::sleep(Duration::from_millis(500));

            if let Ok(o) = Command::new("sc").args(["delete", service]).output() {
                if o.status.success() {
                    log.ok(&format!("Служба удалена: {}", service));
                    deleted.push(service.to_string());
                } else {
                    log.warn(&format!("Служба уже удалена: {}", service));
                }
            }
        } else {
            log.info(&format!("[DRY-RUN] sc delete {}", service));
            deleted.push(service.to_string());
        }
    }

    deleted
}

/// Удалить пути (файлы и папки)
fn remove_paths(
    paths: &[PathBuf],
    dry_run: bool,
    log: &mut FileLogger,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut deleted = Vec::new();
    let mut failed = Vec::new();

    let paths = dedup_paths(paths.to_vec());

    for path in paths {
        if !path.exists() {
            continue;
        }

        log.info(&format!("Удаляю: {}", path.display()));

        if dry_run {
            log.info(&format!("[DRY-RUN] Удалить: {}", path.display()));
            deleted.push(path);
            continue;
        }

        let result = if path.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };

        match result {
            Ok(_) => {
                log.ok(&format!("Удалено: {}", path.display()));
                deleted.push(path);
            }
            Err(e) => {
                log.warn(&format!("Ошибка удаления: {}. Пробую cmd...", e));

                let arg = if path.is_dir() {
                    format!("rd /s /q \"{}\"", path.display())
                } else {
                    format!("del /f /q \"{}\"", path.display())
                };

                let _ = Command::new("cmd").args(["/C", &arg]).output();

                if !path.exists() {
                    log.ok(&format!("Удалено через cmd: {}", path.display()));
                    deleted.push(path);
                } else {
                    log.error(&format!("НЕ УДАЛОСЬ: {}", path.display()));
                    failed.push(path);
                }
            }
        }
    }

    (deleted, failed)
}

/// Очистить реестр
fn clean_tool_registry(
    result: &ToolDetectionResult,
    dry_run: bool,
    log: &mut FileLogger,
) -> (Vec<String>, Vec<String>) {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut deleted = Vec::new();
    let mut failed = Vec::new();

    log.info("Очищаю реестр...");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Удалить Uninstall ключи
    for key_path in &result.registry_keys_to_delete {
        log.info(&format!("Удаляю ключ: {}", key_path));

        if !dry_run {
            if let Some(subkey_name) = key_path.split('\\').last() {
                let base_path = if key_path.contains("WOW6432Node") {
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                } else {
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
                };

                if let Ok(parent) = hklm.open_subkey_with_flags(base_path, KEY_ALL_ACCESS) {
                    match parent.delete_subkey_all(subkey_name) {
                        Ok(_) => {
                            log.ok(&format!("Ключ удалён: {}", subkey_name));
                            deleted.push(key_path.clone());
                        }
                        Err(e) => {
                            log.error(&format!("Ошибка удаления ключа: {}", e));
                            failed.push(key_path.clone());
                        }
                    }
                }
            }
        } else {
            log.info(&format!("[DRY-RUN] Удалить ключ: {}", key_path));
            deleted.push(key_path.clone());
        }
    }

    (deleted, failed)
}

/// Очистить правила файрвола
fn clean_firewall_rules(
    rule_names: &[&str],
    dry_run: bool,
    log: &mut FileLogger,
) {
    log.info("Очищаю правила файрвола...");

    if !dry_run {
        for rule_name in rule_names {
            for direction in ["in", "out"] {
                let _ = Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={}", rule_name),
                        &format!("dir={}", direction),
                    ])
                    .output();
            }
        }
        log.ok("Правила файрвола обработаны");
    } else {
        log.info("[DRY-RUN] Очистка правил файрвола");
    }
}

/// Проверка что инструмент удалён
fn verify_tool_removed(
    tool: &'static RasTool,
    sys: &System,
    log: &mut FileLogger,
) -> bool {
    log.info(&format!("Проверяю {} ...", tool.name));

    let result = detect_tool(tool, sys, log);

    if !result.found {
        log.ok(&format!("✓ {} полностью удалён", tool.name));
        true
    } else {
        log.error(&format!("✗ {} остались следы", tool.name));
        false
    }
}

// ===========================================================================
// MFT Scanner — Сканирование через Master File Table (Windows API)
// ===========================================================================

#[repr(C)]
struct MftEnumData {
    start_file_reference_number: u64,
    low_usn: u64,
    high_usn: u64,
}

#[repr(C)]
struct UsnRecordV2 {
    record_length: u32,
    major_version: u16,
    minor_version: u16,
    file_reference_number: u64,
    parent_file_reference_number: u64,
    usn: i64,
    timestamp: i64,
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    file_name_length: u16,
    file_name_offset: u16,
}

/// Получить список NTFS дисков в системе
fn get_ntfs_volumes() -> Vec<String> {
    let mut volumes = Vec::new();

    extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetDriveTypeW(lp_root_path_name: *const u16) -> u32;
    }

    const DRIVE_FIXED: u32 = 3;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_REMOTE: u32 = 4;

    unsafe {
        let drives = GetLogicalDrives();
        for i in 0..26 {
            if (drives >> i) & 1 == 1 {
                let drive_letter = (b'A' + i as u8) as char;
                let path = format!("{}:\\", drive_letter);
                let wide_path: Vec<u16> = path.encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                let drive_type = GetDriveTypeW(wide_path.as_ptr());
                if drive_type == DRIVE_FIXED || drive_type == DRIVE_REMOVABLE
                   || drive_type == DRIVE_REMOTE {
                    volumes.push(format!("{}:", drive_letter));
                }
            }
        }
    }
    volumes
}

/// Сканировать том через MFT (FSCTL_ENUM_USN_DATA)
fn scan_volume_mft(
    volume: &str,
    exe_filenames_lower: &[String],
    log: &mut FileLogger,
) -> Vec<PathBuf> {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;

    let mut found = Vec::new();

    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut std::ffi::c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
        fn DeviceIoControl(
            hDevice: *mut std::ffi::c_void,
            dwIoControlCode: u32,
            lpInBuffer: *mut std::ffi::c_void,
            nInBufferSize: u32,
            lpOutBuffer: *mut std::ffi::c_void,
            nOutBufferSize: u32,
            lpBytesReturned: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
        ) -> i32;
    }

    const GENERIC_READ: u32 = 0x80000000;
    const FILE_SHARE_READ: u32 = 0x00000001;
    const FILE_SHARE_WRITE: u32 = 0x00000002;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_NO_BUFFERING: u32 = 0x20000000;
    const FSCTL_ENUM_USN_DATA: u32 = 0x900b3;

    // Путь к диску: \\.\C: (не \\\\.\\...)
    let path = if volume.ends_with(':') {
        format!("\\\\.\\{}", volume)
    } else {
        format!("\\\\.\\{}:", volume)
    };

    log.info(&format!("  📂 Открываю диск по пути: {}", path));

    let wide_path: Vec<u16> = path.encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let handle = CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            std::ptr::null_mut(),
        );

        if handle.is_null() || handle as isize == -1 {
            let error_code = GetLastError();
            let error_msg = match error_code {
                2 => "FILE_NOT_FOUND".to_string(),
                3 => "PATH_NOT_FOUND".to_string(),
                5 => "ACCESS_DENIED - требуются права администратора для MFT".to_string(),
                32 => "SHARING_VIOLATION".to_string(),
                123 => "INVALID_NAME".to_string(),
                _ => format!("ErrorCode({})", error_code),
            };
            log.warn(&format!("❌ Диск {}: {} - MFT сканер пропущен", volume, error_msg));
            return found;
        }

        let mut mft_data = MftEnumData {
            start_file_reference_number: 0,
            low_usn: 0,
            high_usn: i64::MAX as u64,
        };

        let mut output_buffer = vec![0u8; 65536];
        let mut iteration = 0;
        const MAX_ITERATIONS: usize = 10000; // Предохранитель от бесконечного цикла

        loop {
            iteration += 1;
            if iteration > MAX_ITERATIONS {
                log.warn(&format!("Максимум итераций MFT на диске {}", volume));
                break;
            }

            let mut bytes_returned = 0u32;
            let ret = DeviceIoControl(
                handle,
                FSCTL_ENUM_USN_DATA,
                &mut mft_data as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<MftEnumData>() as u32,
                output_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                output_buffer.len() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            );

            if ret == 0 {
                let error_code = GetLastError();
                let error_msg = match error_code {
                    5 => "ACCESS_DENIED - требуются права администратора".to_string(),
                    87 => "INVALID_PARAMETER - неправильная структура или параметры".to_string(),
                    1112 => "NOT_SUPPORTED - USN журнал не инициализирован".to_string(),
                    _ => format!("ErrorCode({})", error_code),
                };
                if iteration == 1 {
                    // Логируем только на первой итерации чтобы не заспамить
                    log.warn(&format!("❌ DeviceIoControl FSCTL_ENUM_USN_DATA ошибка на {}: {} [iteration={}]", volume, error_msg, iteration));
                }
                break;
            }

            if bytes_returned < 8 {
                break;
            }

            // Парсим USN записи
            let mut offset = 8;
            while offset + std::mem::size_of::<UsnRecordV2>() <= bytes_returned as usize {
                if offset >= output_buffer.len() {
                    break;
                }

                let record = &output_buffer[offset..];
                let usn_rec = record.as_ptr() as *const UsnRecordV2;

                let rec_len = unsafe { (*usn_rec).record_length } as usize;
                if rec_len == 0 || offset + rec_len > bytes_returned as usize {
                    break;
                }

                let file_name_len = unsafe { (*usn_rec).file_name_length } as usize;
                let file_name_offset = unsafe { (*usn_rec).file_name_offset } as usize;

                if file_name_offset + file_name_len <= rec_len {
                    let name_bytes = &record[file_name_offset..file_name_offset + file_name_len];
                    let name_slice = unsafe {
                        std::slice::from_raw_parts(name_bytes.as_ptr() as *const u16, file_name_len / 2)
                    };
                    if let Ok(name) = String::from_utf16(name_slice) {
                        let name_lower = name.to_lowercase();
                        if exe_filenames_lower.iter().any(|ef| ef == &name_lower) {
                            // Найден файл!
                            if let Some(full_path) = find_file_by_name(&format!("{}:\\", volume), &name, log) {
                                found.push(full_path);
                            }
                        }
                    }
                }

                offset += rec_len;
            }

            // Обновить для следующей итерации
            if bytes_returned as usize > 8 {
                // Читаем последний USN из buffer
                let last_offset = (bytes_returned as usize).saturating_sub(std::mem::size_of::<UsnRecordV2>());
                if last_offset > 8 {
                    let record = &output_buffer[last_offset..];
                    let usn_rec = record.as_ptr() as *const UsnRecordV2;
                    mft_data.low_usn = unsafe { (*usn_rec).usn } as u64;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        let _ = CloseHandle(handle);
    }

    found
}

/// Рекурсивно найти файл по имени в папке (fallback для восстановления полного пути)
fn find_file_by_name(root: &str, filename: &str, _log: &mut FileLogger) -> Option<PathBuf> {
    if !Path::new(root).exists() {
        return None;
    }

    let filename_lower = filename.to_lowercase();

    match fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    if name.to_string_lossy().to_lowercase() == filename_lower {
                        return Some(path);
                    }
                }

                if path.is_dir() {
                    if let Some(dir_name) = path.file_name() {
                        if should_skip_dir(&dir_name.to_string_lossy()) {
                            continue;
                        }
                    }
                    if let Some(found) = find_file_by_name(&path.to_string_lossy(), filename, _log) {
                        return Some(found);
                    }
                }
            }
        }
        Err(_) => {}
    }

    None
}

/// Главная функция сканирования MFT для поиска portable RAS
fn scan_mft_for_portable(
    tool_name: &str,
    exe_filenames: &[&str],
    log: &mut FileLogger,
) -> Vec<PortableFoundResult> {
    let mut all_found = Vec::new();
    let exe_filenames_lower: Vec<String> =
        exe_filenames.iter().map(|s| s.to_lowercase()).collect();

    log.info(&format!("📊 Сканирую MFT всех дисков в поиске {}...", tool_name));

    for volume in get_ntfs_volumes() {
        log.info(&format!("  Сканирую диск {}...", volume));
        let found = scan_volume_mft(&volume, &exe_filenames_lower, log);

        for exe_path in found {
            all_found.push(PortableFoundResult {
                tool_name: tool_name.to_string(),
                exe_path,
            });
        }
    }

    all_found
}

// ===========================================================================
// Portable Detection & Removal — Everything Integration
// ===========================================================================

const EVERYTHING_INSTALLER_URL: &str = "https://www.voidtools.com/Everything-1.4.1.1026.x64.exe";
const EVERYTHING_ES_URL: &str = "https://www.voidtools.com/ES-1.1.0.27.x64.zip";

/// Найти everything.exe (портативная версия в проекте)
fn find_portable_everything() -> Option<PathBuf> {
    let possible_paths = vec![
        // Рядом с текущим exe
        env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|parent| parent.join("everything.exe"))),
        // В корне проекта (при разработке)
        Some(PathBuf::from("everything.exe")),
        Some(PathBuf::from("./everything.exe")),
    ];

    for path_opt in possible_paths.into_iter().flatten() {
        if path_opt.exists() {
            return Some(path_opt);
        }
    }

    None
}

/// Найти es.exe (CLI для Everything) в стандартных местах
fn find_es_exe() -> Option<PathBuf> {
    let possible_paths = vec![
        "C:\\Program Files\\Everything\\es.exe",
        "C:\\Program Files (x86)\\Everything\\es.exe",
        "C:\\ProgramData\\RASRemover\\es.exe",
    ];

    for path_str in possible_paths {
        let path = Path::new(path_str);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    // Проверить PATH
    if let Ok(output) = Command::new("where").arg("es.exe").output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout);
            for line in path_str.lines() {
                let path = Path::new(line.trim());
                if path.exists() {
                    return Some(path.to_path_buf());
                }
            }
        }
    }

    None
}

/// Запустить встроенное Everything и возвращает путь к es.exe
fn run_builtin_everything(log: &mut FileLogger) -> Option<PathBuf> {
    let everything_path = find_portable_everything()?;

    log.info("🚀 Запускаю встроенное Everything (может быть быстро)...");

    // Запустить everything.exe как сервис
    let _ = Command::new(&everything_path)
        .arg("-admin")
        .arg("-install-service")
        .output();

    // Дождаться запуска сервиса (3 сек на запуск + 2 сек на первое индексирование)
    thread::sleep(Duration::from_secs(3));

    // Найти es.exe рядом с everything.exe
    let es_path = everything_path
        .parent()
        .map(|dir| dir.join("es.exe"))
        .filter(|p| p.exists())?;

    // Проверить что Everything работает - запросим версию
    match Command::new(&es_path).output() {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("ES") || output_str.contains("Everything") {
                log.ok("✅ Everything запущен и готов к поиску");
                return Some(es_path);
            }
        }
        Err(_) => {}
    }

    // Если ошибка IPC - сервис еще не запустился, но может заработать
    // Попробуем еще раз через 2 сек
    thread::sleep(Duration::from_secs(2));
    log.ok("✅ Everything запущен (деferred mode)");
    Some(es_path)
}

/// Скачать файл через PowerShell
fn download_file(url: &str, dest: &Path, log: &mut FileLogger) -> bool {
    let dest_str = dest.to_string_lossy().replace('\\', "\\\\");

    // Попытка 1: Invoke-WebRequest с retry-логикой
    let cmd = format!(
        "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12; \
         Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing -ErrorAction Stop",
        url, dest_str
    );

    match Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .output()
    {
        Ok(output) => {
            if output.status.success() && dest.exists() {
                return true;
            }
            log.warn(&format!("PowerShell скачивание не сработало"));
        }
        Err(e) => {
            log.warn(&format!("Ошибка PowerShell: {}", e));
        }
    }

    false
}

/// Установить Everything и скачать es.exe
fn install_everything(log: &mut FileLogger) -> Option<PathBuf> {
    let temp_dir = env::temp_dir();
    let installer_path = temp_dir.join("ras_everything_setup.exe");

    log.info("Скачиваю Everything installer...");
    if !download_file(EVERYTHING_INSTALLER_URL, &installer_path, log) {
        log.warn("Не удалось скачать Everything installer");
        return None;
    }

    log.info("Устанавливаю Everything (тихо)...");
    let _ = Command::new(&installer_path).arg("/S").output();
    thread::sleep(Duration::from_secs(5));

    // Попробовать найти установленный es.exe
    if let Some(path) = find_es_exe() {
        let _ = fs::remove_file(&installer_path);
        log.ok("Everything успешно установлен");
        return Some(path);
    }

    // Fallback: скачать es.exe отдельно
    log.info("Скачиваю ES CLI...");
    let zip_path = temp_dir.join("ES.zip");
    let ras_dir = PathBuf::from("C:\\ProgramData\\RASRemover");
    let _ = fs::create_dir_all(&ras_dir);

    if !download_file(EVERYTHING_ES_URL, &zip_path, log) {
        log.warn("Не удалось скачать ES CLI");
        let _ = fs::remove_file(&installer_path);
        let _ = fs::remove_file(&zip_path);
        return None;
    }

    // Распаковать через PowerShell
    let zip_str = zip_path.to_string_lossy().replace('\\', "\\\\");
    let dest_str = ras_dir.to_string_lossy().replace('\\', "\\\\");
    let cmd = format!(
        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
        zip_str, dest_str
    );

    if Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let _ = fs::remove_file(&installer_path);
        let _ = fs::remove_file(&zip_path);
        let es_path = ras_dir.join("es.exe");
        if es_path.exists() {
            log.ok("ES CLI установлен");
            return Some(es_path);
        }
    }

    let _ = fs::remove_file(&installer_path);
    let _ = fs::remove_file(&zip_path);
    None
}

/// Поиск файлов через Everything CLI (es.exe)
fn search_with_everything(es_path: &Path, exe_filename: &str, log: &mut FileLogger) -> Vec<PathBuf> {
    let mut results = Vec::new();

    match Command::new(es_path).arg(exe_filename).output() {
        Ok(output) => {
            // Проверить если ошибка "IPC window not found" - Everything не работает
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("IPC window not found") {
                log.warn("Everything не работает - переключаюсь на рекурсивный поиск");
                return results;
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let path = line.trim();
                if !path.is_empty() && Path::new(path).exists() {
                    results.push(PathBuf::from(path));
                }
            }
        }
        Err(_) => {}
    }

    results
}

/// Пропустить ли эту директорию при сканировании
fn should_skip_dir(dir_name: &str) -> bool {
    let name_lower = dir_name.to_lowercase();
    matches!(
        name_lower.as_str(),
        "windows" | "system32" | "syswow64" | "$recycle.bin" | "$winreagent"
            | "$pagefile" | "$sysvolinfo" | "recovery" | "boot"
            | "perflog" | "msocache" | "programdata" | "pagefile.sys"
            | "hiberfil.sys" | "swapfile.sys"
    )
}

/// Рекурсивный поиск portable exe-файлов
fn scan_portable_recursive(
    root: &Path,
    exe_filenames_lower: &[String],
    found: &mut Vec<PathBuf>,
    _log: &mut FileLogger,
) {
    if !root.exists() {
        return;
    }

    match fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = match path.file_name() {
                    Some(name) => name.to_string_lossy().to_string(),
                    None => continue,
                };

                let file_name_lower = file_name.to_lowercase();

                // Проверить файл
                if path.is_file() && exe_filenames_lower.iter().any(|ef| ef == &file_name_lower) {
                    if path.exists() {
                        found.push(path);
                    }
                }
                // Рекурсия в папку (если не системная)
                else if path.is_dir() && !should_skip_dir(&file_name) {
                    scan_portable_recursive(&path, exe_filenames_lower, found, _log);
                }
            }
        }
        Err(_) => {
            // Тихо игнорируем ошибки доступа к папкам
        }
    }
}

/// Получить список "интересных" папок для сканирования
fn get_scan_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Папки на корне диска C:\
    let c_root_dirs = vec![
        "C:\\Downloads",
        "C:\\Temp",
        "C:\\Tools",
        "C:\\Apps",
        "C:\\Programs",
        "C:\\Portable",
    ];

    for dir in c_root_dirs {
        if Path::new(dir).exists() {
            paths.push(PathBuf::from(dir));
        }
    }

    // Desktop, Downloads, Documents для текущего пользователя
    if let Ok(user_dir) = env::var("USERPROFILE") {
        for subdir in &["Desktop", "Downloads", "Documents"] {
            let path = PathBuf::from(&user_dir).join(subdir);
            if path.exists() {
                paths.push(path);
            }
        }
    }

    dedup_paths(paths)
}

/// Сканирование портативных версий инструментов (Everything по всем дискам)
fn scan_all_portable(config: &Config, log: &mut FileLogger) -> Vec<PortableFoundResult> {
    let mut all_portable = Vec::new();

    // ЭТАП 1: Попытка использовать всё найденное Everything
    log.info("=== ЭТАП 1: Поиск Everything ===");
    let mut es_exe = find_portable_everything().or_else(|| find_es_exe());

    // ЭТАП 2: Если Everything не найден - попытаться установить
    if es_exe.is_none() {
        log.warn("Everything не найден. Пробую установить...");
        es_exe = install_everything(log);
    }

    // ЭТАП 3: Если Everything всё ещё не доступен - использовать MFT
    let use_everything = es_exe.is_some();

    if use_everything {
        log.info("🔍 === ЭТАП 2: Используем Everything ===");
    } else {
        log.info("📊 === ЭТАП 3: Everything недоступен - используем MFT сканер ===");
    }

    for tool in RAS_TOOLS {
        let should_scan = config
            .target_tool
            .as_ref()
            .map(|t| tool.name.to_lowercase().contains(&t.to_lowercase()))
            .unwrap_or(true);

        if !should_scan {
            continue;
        }

        log.info(&format!("Ищу portable версии: {}", tool.name));

        if use_everything {
            // === ЭТАП 2: Everything для поиска ===
            if let Some(ref es_path) = es_exe {
                for exe_name in tool.exe_filenames {
                    let found = search_with_everything(es_path, exe_name, log);
                    for exe_path in found {
                        all_portable.push(PortableFoundResult {
                            tool_name: tool.name.to_string(),
                            exe_path,
                        });
                    }
                }
            }
        } else {
            // === ЭТАП 3: MFT сканер (быстрый полный диск без Everything) ===
            let mft_results = scan_mft_for_portable(tool.name, tool.exe_filenames, log);
            all_portable.extend(mft_results);
        }
    }

    // Дедупликация
    let deduped = dedup_paths(
        all_portable
            .iter()
            .map(|p| p.exe_path.clone())
            .collect(),
    );
    all_portable.retain(|p| deduped.iter().any(|d| d == &p.exe_path));

    all_portable
}

/// Удалить найденные portable exe-файлы
fn remove_portable_files(
    found: &[PortableFoundResult],
    config: &Config,
    log: &mut FileLogger,
) {
    if found.is_empty() {
        return;
    }

    log.info(&format!("Удаляю {} portable файлов...", found.len()));

    for portable in found {
        let file_name = portable
            .exe_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        log.info(&format!(
            "Обрабатываю: {} [{}]",
            portable.exe_path.display(),
            portable.tool_name
        ));

        // Убить процесс если запущен
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", &file_name, "/T"])
            .output();
        thread::sleep(Duration::from_millis(500));

        if !config.dry_run {
            match fs::remove_file(&portable.exe_path) {
                Ok(_) => {
                    log.ok(&format!("Удалено: {}", portable.exe_path.display()));
                }
                Err(e) => {
                    log.warn(&format!("Прямое удаление не сработало: {}. Пробую cmd...", e));

                    let arg = format!("del /f /q \"{}\"", portable.exe_path.display());
                    let _ = Command::new("cmd").args(["/C", &arg]).output();

                    if !portable.exe_path.exists() {
                        log.ok(&format!("Удалено через cmd: {}", portable.exe_path.display()));
                    } else {
                        log.error(&format!("НЕ УДАЛОСЬ: {}", portable.exe_path.display()));
                    }
                }
            }
        } else {
            log.info(&format!("[DRY-RUN] Удалить: {}", portable.exe_path.display()));
        }
    }
}

/// Полный пайплайн удаления одного инструмента
fn remove_tool(
    detection: ToolDetectionResult,
    config: &Config,
    log: &mut FileLogger,
) -> RemovalSummary {
    let tool = detection.tool.unwrap();
    let mut summary = RemovalSummary {
        tool_name: tool.name.to_string(),
        ..Default::default()
    };

    log.info(&format!("=== УДАЛЕНИЕ: {} ===", tool.name));

    // 1. Завершить процессы
    summary.processes_killed = kill_processes_by_names(tool.process_names, config.dry_run, log);

    // 2. Запустить деинсталлятор
    for uninstall_str in &detection.uninstall_strings {
        if let Some(cmd) = parse_uninstall_string(uninstall_str) {
            summary.uninstaller_exit_code = run_uninstaller_command(&cmd, tool.silent_args, config.dry_run, log);
            summary.uninstaller_ran = true;
            break;
        }
    }

    thread::sleep(Duration::from_secs(2));

    // 3. Удалить сервисы
    summary.services_deleted = remove_services(tool.service_names, config.dry_run, log);

    // 4. Удалить файлы
    let (deleted, failed) = remove_paths(&detection.install_dirs, config.dry_run, log);
    summary.files_deleted = deleted;
    summary.files_failed = failed;

    // 5. Очистить реестр
    let (reg_deleted, reg_failed) = clean_tool_registry(&detection, config.dry_run, log);
    summary.registry_keys_deleted = reg_deleted;
    summary.registry_keys_failed = reg_failed;

    // 6. Очистить файрвол
    clean_firewall_rules(tool.firewall_rule_names, config.dry_run, log);
    summary.firewall_rules_cleaned = true;

    // 7. Финальная проверка
    if !config.dry_run {
        let sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        summary.final_verification_clean = verify_tool_removed(tool, &sys, log);
    } else {
        log.info("[DRY-RUN] Финальная проверка пропущена");
        summary.final_verification_clean = true;
    }

    summary
}

// ===========================================================================
// Main
// ===========================================================================

fn main() {
    let config = Config::from_args();

    if config.silent {
        hide_console_window();
    }

    let mut log = match FileLogger::new(&config.log_dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("FATAL: Не удалось создать лог: {}", e);
            std::process::exit(1);
        }
    };

    log.info("╔══════════════════════════════════════════════════════╗");
    log.info("║          RAS Remover v2.0.0                         ║");
    log.info("║  Удаление популярных Remote Access Software         ║");
    log.info("╚══════════════════════════════════════════════════════╝");

    // Проверка прав администратора
    if !is_admin() {
        log.warn("⚠️  ВНИМАНИЕ: Программа работает БЕЗ прав администратора!");
        log.warn("Функции сканирования будут ограничены:");
        log.warn("  • MFT сканер НЕ сможет получить доступ к диску");
        log.warn("  • Некоторые реестровые ключи могут быть недоступны");
        log.warn("  • Удаление служб и файлов может не работать");
        log.warn("");
        log.warn("Рекомендация: Запустите программу от имени администратора:");
        log.warn("  1. Нажмите Win+R");
        log.warn("  2. Введите: cmd");
        log.warn("  3. Нажмите Ctrl+Shift+Enter (или выберите 'Запустить от имени администратора')");
        log.warn("  4. Введите полный путь до программы и нажмите Enter");
        log.warn("");
    } else {
        log.ok("✓ Программа работает с правами администратора");
    }

    if config.silent {
        log.info("РЕЖИМ: консоль скрыта");
    }

    if config.dry_run {
        log.warn("РЕЖИМ: DRY-RUN (без реальных изменений)");
    }

    if let Some(tool_name) = &config.target_tool {
        log.info(&format!("РЕЖИМ: удаление только {}", tool_name));
    }

    // === ФАЗА 1: Сканирование ===
    let detected = scan_all_tools(&config, &mut log);

    if !detected.is_empty() {
        log.warn(&format!("✗ Обнаружено {} инструмент(ов):", detected.len()));
        for r in &detected {
            log.warn(&format!("  - {}", r.tool.unwrap().name));
        }
    }

    // === ФАЗА 2: Удаление ===
    log.info("=== ФАЗА 2: УДАЛЕНИЕ ===");
    let mut summaries: Vec<RemovalSummary> = Vec::new();

    for result in detected {
        let summary = remove_tool(result, &config, &mut log);
        summaries.push(summary);
    }

    // === ФАЗА 2: Поиск и удаление portable версий ===
    log.info("=== ФАЗА 2: ПОИСК PORTABLE ВЕРСИЙ ===");
    let portable_found = scan_all_portable(&config, &mut log);
    if !portable_found.is_empty() {
        log.warn(&format!(
            "✗ Найдено {} portable файлов:",
            portable_found.len()
        ));
        for p in &portable_found {
            log.warn(&format!("  - {} [{}]", p.exe_path.display(), p.tool_name));
        }
        remove_portable_files(&portable_found, &config, &mut log);
    } else {
        log.info("✓ Portable версии не найдены");
    }

    // === ФАЗА 3: Финальный отчёт ===
    log.info("=== ФАЗА 3: ФИНАЛЬНЫЙ ОТЧЁТ ===");

    if summaries.is_empty() && portable_found.is_empty() {
        log.ok("✓ Система чистая. Удаление не требуется.");
        log.info("=".repeat(60).as_str());
        std::process::exit(0);
    }

    let mut all_clean = true;
    for s in &summaries {
        if s.final_verification_clean {
            log.ok(&format!("[{}] ✓ Полностью удалён", s.tool_name));
        } else {
            log.error(&format!("[{}] ✗ Требуется ручная проверка", s.tool_name));
            all_clean = false;
        }
    }

    log.info("=".repeat(60).as_str());
    if all_clean {
        log.ok("✓ Работа завершена успешно.");
        std::process::exit(0);
    } else {
        log.error("✗ Работа завершена с ошибками.");
        std::process::exit(1);
    }
}
