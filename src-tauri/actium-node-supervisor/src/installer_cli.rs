use actium_node_core::{SupervisorClient, SupervisorCommand, SupervisorReply, SUPERVISOR_VERSION};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ])
            .output();
        if let Ok(out) = output {
            let str_val = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            return str_val == "true";
        }
        false
    }
    #[cfg(unix)]
    {
        nix::unistd::Uid::current().is_root()
    }
}

pub fn find_supervisor_script(script_name: &str) -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));

    let candidates = [
        exe_dir.join(script_name),
        exe_dir.join("supervisor").join(script_name),
        exe_dir.join("..").join("supervisor").join(script_name),
        exe_dir.join("..").join("resources").join("supervisor").join(script_name),
        exe_dir.join("..").join("..").join("supervisor").join(script_name),
        exe_dir.join("..").join("..").join("src-tauri").join("supervisor").join(script_name),
        exe_dir.join("..").join("..").join("src-tauri").join("resources").join("supervisor").join(script_name),
        PathBuf::from(r"C:\Program Files\Actium Node Manager\resources\supervisor").join(script_name),
        PathBuf::from(r"C:\ProgramData\Actium\NodeManager\bin").join(script_name),
        PathBuf::from(r"C:\ProgramData\Actium\NodeManagerLab\bin").join(script_name),
        PathBuf::from("/usr/lib/Actium Node Manager/supervisor").join(script_name),
        PathBuf::from("/usr/lib/actium-node-manager/supervisor").join(script_name),
    ];

    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }

    Err(format!(
        "No se pudo encontrar {script_name} en las rutas estándar. Ubicación del binario: {}",
        exe_dir.display()
    ))
}

#[cfg(windows)]
pub fn find_optional_payload_dir() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));

    let candidates = [
        exe_dir.join("payload"),
        exe_dir.join("..").join("node"),
        exe_dir.join("..").join("payload"),
        exe_dir.join("resources").join("node"),
        exe_dir.join("..").join("resources").join("node"),
        exe_dir.join("..").join("..").join("node"),
        exe_dir.join("..").join("..").join("resources").join("node"),
        exe_dir.join("..").join("..").join("src-tauri").join("resources").join("node"),
        exe_dir.join("..").join("..").join("..").join("resources").join("node"),
        exe_dir.join("..").join("..").join("..").join("src-tauri").join("resources").join("node"),
        PathBuf::from(r"C:\Program Files\Actium Node Manager\node"),
        PathBuf::from(r"C:\Program Files\Actium Node Manager\resources\node"),
        PathBuf::from(r"C:\ProgramData\Actium\NodeManager\payload"),
        PathBuf::from(r"C:\ProgramData\Actium\NodeManagerLab\payload"),
        PathBuf::from("/usr/lib/Actium Node Manager/node"),
        PathBuf::from("/usr/lib/Actium Node Manager/resources/node"),
        PathBuf::from("/usr/lib/actium-node-manager/node"),
        PathBuf::from("/usr/lib/actium-node-manager/resources/node"),
        PathBuf::from("/usr/lib/actium/node-manager/payload"),
        PathBuf::from("/usr/lib/actium/node-manager-lab/payload"),
    ];

    for candidate in &candidates {
        if candidate.join("PAYLOAD.json").is_file() {
            return Some(candidate.clone());
        }
    }

    None
}

pub fn install_channel(channel: &str, no_start: bool) -> Result<(), String> {
    if channel == "both" || channel == "all" {
        println!("Aprovisionando ambos canales: Stable y Lab...");
        install_channel("stable", no_start)?;
        install_channel("lab", no_start)?;
        return Ok(());
    }

    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let payload_dir = find_optional_payload_dir();
    #[cfg(not(windows))]
    let payload_dir: Option<PathBuf> = None;

    println!("Iniciando aprovisionamiento de Actium Node Supervisor [{channel}]...");
    println!("  Binario: {}", current_exe.display());
    println!(
        "  Product Extension Bundle: {}",
        payload_dir
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "NO_EXTENSIONS (Base Runtime)".to_string())
    );

    #[cfg(windows)]
    {
        let script = find_supervisor_script("install-supervisor-windows.ps1")?;
        let elevated = is_elevated();

        if elevated {
            let mut cmd = Command::new("powershell");
            cmd.args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script.to_str().unwrap(),
                "-Binary",
                current_exe.to_str().unwrap(),
                "-Channel",
                channel,
            ]);
            #[cfg(windows)]
            if let Some(payload_dir) = &payload_dir {
                cmd.args(["-Payload", payload_dir.to_str().unwrap()]);
            }
            if no_start {
                cmd.arg("-NoStart");
            }
            let status = cmd.status().map_err(|e| format!("Fallo al ejecutar PowerShell: {e}"))?;
            if !status.success() {
                return Err(format!("El instalador PowerShell finalizo con error: {status}"));
            }
        } else {
            println!("Solicitando permisos de Administrador (UAC)...");
            let mut arg_list = format!(
                "-NoProfile -ExecutionPolicy Bypass -File \"{}\" -Binary \"{}\" -Channel \"{}\"",
                script.display(),
                current_exe.display(),
                channel
            );
            #[cfg(windows)]
            if let Some(payload_dir) = &payload_dir {
                arg_list.push_str(&format!(" -Payload \"{}\"", payload_dir.display()));
            }
            if no_start {
                arg_list.push_str(" -NoStart");
            }

            let status = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Start-Process powershell.exe -ArgumentList '{arg_list}' -Verb RunAs -Wait"),
                ])
                .status()
                .map_err(|e| format!("Fallo al solicitar elevacion UAC: {e}"))?;

            if !status.success() {
                return Err("La instalacion con elevacion UAC fue cancelada o rechazada.".to_string());
            }
        }
    }

    #[cfg(unix)]
    {
        let script = find_supervisor_script("install-supervisor-debian.sh")?;
        let mut cmd = if is_elevated() {
            let mut c = Command::new("sh");
            c.arg(script.to_str().unwrap());
            c
        } else {
            println!("Solicitando permisos de root (sudo)...");
            let mut c = Command::new("sudo");
            c.arg("sh").arg(script.to_str().unwrap());
            c
        };

        cmd.args([
            "--binary",
            current_exe.to_str().unwrap(),
            "--channel",
            channel,
        ]);
        // Linux first install is Base Runtime only. Legacy Aegis payload
        // discovery is deliberately excluded from this path.
        if no_start {
            cmd.arg("--no-start");
        }

        let status = cmd.status().map_err(|e| format!("Fallo al ejecutar script: {e}"))?;
        if !status.success() {
            return Err(format!("El script de instalacion finalizo con error: {status}"));
        }
    }

    println!("Aprovisionamiento de [{channel}] completado exitosamente.");
    if !no_start {
        println!("Comprobando comunicacion con el servicio...");
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = ping_channel(channel);
    }

    Ok(())
}

pub fn uninstall_channel(channel: &str, remove_data: bool) -> Result<(), String> {
    if channel == "both" || channel == "all" {
        println!("Desinstalando ambos canales: Stable y Lab...");
        uninstall_channel("stable", remove_data)?;
        uninstall_channel("lab", remove_data)?;
        return Ok(());
    }

    println!("Desinstalando servicio de Actium Node Supervisor [{channel}]...");
    #[cfg(windows)]
    {
        let script = find_supervisor_script("uninstall-supervisor-windows.ps1")?;
        let elevated = is_elevated();

        if elevated {
            let mut cmd = Command::new("powershell");
            cmd.args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script.to_str().unwrap(),
                "-Channel",
                channel,
            ]);
            if remove_data {
                cmd.arg("-RemoveData");
            }
            let status = cmd.status().map_err(|e| format!("Fallo al ejecutar PowerShell: {e}"))?;
            if !status.success() {
                return Err(format!("Desinstalador fallo: {status}"));
            }
        } else {
            println!("Solicitando permisos de Administrador (UAC)...");
            let mut arg_list = format!(
                "-NoProfile -ExecutionPolicy Bypass -File \"{}\" -Channel \"{}\"",
                script.display(),
                channel
            );
            if remove_data {
                arg_list.push_str(" -RemoveData");
            }
            let status = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Start-Process powershell.exe -ArgumentList '{arg_list}' -Verb RunAs -Wait"),
                ])
                .status()
                .map_err(|e| format!("Fallo al solicitar elevacion UAC: {e}"))?;
            if !status.success() {
                return Err("Desinstalacion cancelada o rechazada.".to_string());
            }
        }
    }
    #[cfg(unix)]
    {
        let service = if channel == "lab" {
            "actium-node-supervisor-lab.service"
        } else {
            "actium-node-supervisor.service"
        };
        let _ = Command::new("sudo").args(["systemctl", "stop", service]).status();
        let _ = Command::new("sudo").args(["systemctl", "disable", service]).status();
        let _ = Command::new("sudo").args(["rm", "-f", &format!("/etc/systemd/system/{service}")]).status();
        let _ = Command::new("sudo").args(["systemctl", "daemon-reload"]).status();
        if remove_data {
            let root = if channel == "lab" { "/srv/actium-lab" } else { "/srv/actium-data" };
            let _ = Command::new("sudo").args(["rm", "-rf", root]).status();
        }
    }
    println!("Servicio [{channel}] desinstalado correctamente.");
    Ok(())
}

pub fn ping_channel(channel: &str) -> Result<(), String> {
    let (pipe_or_socket, key_path) = match channel {
        "lab" => {
            #[cfg(windows)]
            {
                (
                    PathBuf::from("ActiumNodeSupervisorLab"),
                    PathBuf::from(r"C:\ProgramData\Actium\NodeManagerLab\config\ipc.key"),
                )
            }
            #[cfg(unix)]
            {
                (
                    PathBuf::from("/run/actium/node-manager-lab.sock"),
                    PathBuf::from("/etc/actium/node-manager-lab/ipc.key"),
                )
            }
        }
        _ => {
            #[cfg(windows)]
            {
                (
                    PathBuf::from("ActiumNodeSupervisor"),
                    PathBuf::from(r"C:\ProgramData\Actium\NodeManager\config\ipc.key"),
                )
            }
            #[cfg(unix)]
            {
                (
                    PathBuf::from("/run/actium/node-manager.sock"),
                    PathBuf::from("/etc/actium/node-manager/ipc.key"),
                )
            }
        }
    };

    if !key_path.is_file() {
        println!("  Canal [{channel}]: NO INSTALADO (falta clave IPC en {})", key_path.display());
        return Err("No instalado".to_string());
    }

    let client = SupervisorClient::new(&pipe_or_socket, &key_path);
    match client.request(SupervisorCommand::Ping) {
        Ok(SupervisorReply::Pong {
            supervisor_version,
            recovered_operations,
            protocol_version,
            features,
            ..
        }) => {
            println!(
                "  Canal [{channel}]: ACTIVO Y CONECTADO\n    Version: {supervisor_version} (Protocolo {protocol_version})\n    Operaciones recuperadas: {recovered_operations}\n    Features: {}",
                features.join(", ")
            );
            Ok(())
        }
        Ok(other) => {
            println!("  Canal [{channel}]: RESPUESTA INESPERADA ({other:?})");
            Err("Respuesta inesperada".to_string())
        }
        Err(err) => {
            println!("  Canal [{channel}]: DESCONECTADO O SERVICIO DETENIDO ({err})");
            Err(err)
        }
    }
}

pub fn ping_all_channels() -> Result<(), String> {
    println!("--- Diagnóstico de Canales Actium Node Supervisor ---");
    let _ = ping_channel("stable");
    let _ = ping_channel("lab");
    println!("------------------------------------------------------");
    Ok(())
}

pub fn run_interactive_menu() -> Result<(), String> {
    loop {
        println!("\n=======================================================");
        println!("   Actium Node Supervisor {SUPERVISOR_VERSION} (Asistente)");
        println!("=======================================================");
        println!("Seleccione una opción:");
        println!("  [1] Instalar / Reconfigurar Servicio (Stable / Lab / Ambos)");
        println!("  [2] Desinstalar Servicio");
        println!("  [3] Diagnostico de Salud y Ping de Canales");
        println!("  [4] Salir");
        print!("\nOpción [1-4]: ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }

        match input.trim() {
            "1" => {
                println!("\nSeleccione el canal a instalar:");
                println!("  [1] Stable (Producción - Puertos 8xxx, Servicio ActiumNodeSupervisor)");
                println!("  [2] Lab (Laboratorio/Staging - Puertos 18xxx, Servicio ActiumNodeSupervisorLab)");
                println!("  [3] Ambos (Dual-Channel en paralelo en este host)");
                println!("  [4] Volver al menú principal");
                print!("\nCanal [1-4]: ");
                let _ = io::stdout().flush();

                let mut ch_input = String::new();
                let _ = io::stdin().read_line(&mut ch_input);
                match ch_input.trim() {
                    "1" => {
                        let _ = install_channel("stable", false);
                    }
                    "2" => {
                        let _ = install_channel("lab", false);
                    }
                    "3" => {
                        println!("\n--- Instalando Canal 1/2: Stable ---");
                        let _ = install_channel("stable", false);
                        println!("\n--- Instalando Canal 2/2: Lab ---");
                        let _ = install_channel("lab", false);
                    }
                    _ => continue,
                }
            }
            "2" => {
                println!("\nSeleccione el canal a desinstalar:");
                println!("  [1] Stable");
                println!("  [2] Lab");
                println!("  [3] Ambos");
                println!("  [4] Volver");
                print!("\nOpción [1-4]: ");
                let _ = io::stdout().flush();

                let mut un_input = String::new();
                let _ = io::stdin().read_line(&mut un_input);
                let channel = match un_input.trim() {
                    "1" => "stable",
                    "2" => "lab",
                    "3" => "both",
                    _ => continue,
                };

                print!("¿Desea eliminar también los datos persistidos? (s/N): ");
                let _ = io::stdout().flush();
                let mut del_input = String::new();
                let _ = io::stdin().read_line(&mut del_input);
                let remove_data = del_input.trim().eq_ignore_ascii_case("s");

                if channel == "both" {
                    let _ = uninstall_channel("stable", remove_data);
                    let _ = uninstall_channel("lab", remove_data);
                } else {
                    let _ = uninstall_channel(channel, remove_data);
                }
            }
            "3" => {
                let _ = ping_all_channels();
            }
            "4" | "q" | "exit" => {
                println!("Saliendo.");
                break;
            }
            _ => {
                println!("Opción inválida.");
            }
        }
    }
    Ok(())
}
