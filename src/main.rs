#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use librustdesk::*;

// ========== 添加的注册验证相关导入 ==========
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{System, SystemExt};
use sha2::{Sha256, Digest};
use std::process;
use std::io::{self, Write};
use std::fs;
use serde::{Serialize, Deserialize};

// ========== 注册信息结构体 ==========
#[derive(Serialize, Deserialize)]
struct Registration {
    machine_code: String,
    expiry_timestamp: u64,
    register_code: String,
}

// ========== 注册验证函数实现 ==========

// 获取机器码（基于硬件信息）
fn get_machine_code() -> String {
    let mut system = System::new_all();
    system.refresh_all();
    
    // 使用CPU、主板、内存等信息生成机器码
    let mut hasher = Sha256::new();
    
    // CPU信息
    if let Some(cpu) = system.cpus().first() {
        hasher.update(cpu.brand().as_bytes());
    }
    
    // 系统信息
    hasher.update(system.name().unwrap_or_default().as_bytes());
    hasher.update(system.kernel_version().unwrap_or_default().as_bytes());
    
    // 内存信息
    hasher.update(system.total_memory().to_string().as_bytes());
    
    let result = hasher.finalize();
    hex::encode(result)
}

// 生成注册码
fn generate_register_code(machine_code: &str, secret_key: &str, expiry_days: u64) -> String {
    let expiry_timestamp = get_current_timestamp() + (expiry_days * 24 * 60 * 60);
    
    let mut hasher = Sha256::new();
    hasher.update(machine_code.as_bytes());
    hasher.update(secret_key.as_bytes());
    hasher.update(expiry_timestamp.to_string().as_bytes());
    
    let result = hasher.finalize();
    format!("{}_{}", hex::encode(result), expiry_timestamp)
}

// 验证注册码
fn verify_register_code(machine_code: &str, secret_key: &str, register_code: &str) -> bool {
    let parts: Vec<&str> = register_code.split('_').collect();
    if parts.len() != 2 {
        return false;
    }
    
    let code = parts[0];
    let expiry_timestamp: u64 = match parts[1].parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    
    // 检查是否过期
    if get_current_timestamp() > expiry_timestamp {
        println!("软件已过期！");
        return false;
    }
    
    // 验证注册码
    let mut hasher = Sha256::new();
    hasher.update(machine_code.as_bytes());
    hasher.update(secret_key.as_bytes());
    hasher.update(expiry_timestamp.to_string().as_bytes());
    
    let expected_code = hex::encode(hasher.finalize());
    expected_code == code
}

// 获取当前时间戳
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// 保存注册信息
fn save_registration(reg: &Registration) -> Result<(), Box> {
    let reg_json = serde_json::to_string(reg)?;
    let encoded = base64::encode(reg_json);
    fs::write("rustdesk_license.dat", encoded)?;
    Ok(())
}

// 读取注册信息
fn load_registration() -> Option {
    if let Ok(encoded) = fs::read_to_string("rustdesk_license.dat") {
        if let Ok(decoded) = base64::decode(encoded) {
            if let Ok(reg_json) = String::from_utf8(decoded) {
                if let Ok(reg) = serde_json::from_str(®_json) {
                    return Some(reg);
                }
            }
        }
    }
    None
}

// 注册流程
fn registration_flow(secret_key: &str) -> bool {
    let machine_code = get_machine_code();
    
    println!("您的机器码是: {}", machine_code);
    println!("请输入注册码: ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let register_code = input.trim();
    
    if verify_register_code(&machine_code, secret_key, register_code) {
        let expiry_timestamp = register_code.split('_').last().unwrap().parse().unwrap();
        
        let reg = Registration {
            machine_code,
            expiry_timestamp,
            register_code: register_code.to_string(),
        };
        
        if save_registration(®).is_ok() {
            println!("注册成功！");
            return true;
        }
    }
    
    println!("注册失败！");
    false
}

// 检查注册状态
fn check_registration(secret_key: &str) -> bool {
    if let Some(reg) = load_registration() {
        // 验证机器码是否匹配
        if reg.machine_code != get_machine_code() {
            return false;
        }
        
        // 验证注册码
        if verify_register_code(®.machine_code, secret_key, ®.register_code) {
            let current_time = get_current_timestamp();
            let remaining_days = (reg.expiry_timestamp - current_time) / (24 * 60 * 60);
            
            if remaining_days <= 7 {
                println!("软件将在 {} 天后过期", remaining_days);
            }
            
            return true;
        }
    }
    false
}

// 防时间篡改检查
fn check_time_tampering() -> bool {
    if let Ok(metadata) = fs::metadata("rustdesk_license.dat") {
        if let Ok(modified_time) = metadata.modified() {
            let modified_timestamp = modified_time
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let current_timestamp = get_current_timestamp();
            
            // 如果文件修改时间晚于当前时间，可能被篡改
            if modified_timestamp > current_timestamp {
                println!("检测到时间异常！");
                return false;
            }
        }
    }
    true
}

// ========== 注册验证包装函数 ==========
fn perform_registration_check() -> bool {
    // 你的密钥，需要保密 - 请修改为您的实际密钥
    let secret_key = "RUSTDESK_SECRET_KEY_2024";
    
    // 检查时间篡改
    if !check_time_tampering() {
        println!("软件验证失败！");
        return false;
    }
    
    // 检查注册状态
    if !check_registration(secret_key) {
        println!("软件未注册或注册已过期！");
        println!("请进行注册...");
        
        if !registration_flow(secret_key) {
            println!("注册失败，程序退出！");
            return false;
        }
    }
    
    true
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
fn main() {
    // 添加注册验证
    if !perform_registration_check() {
        process::exit(1);
    }
    
    if !common::global_init() {
        eprintln!("Global initialization failed.");
        return;
    }
    common::test_rendezvous_server();
    common::test_nat_type();
    common::global_clean();
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "cli",
    feature = "flutter"
)))]
fn main() {
    // 添加注册验证
    if !perform_registration_check() {
        process::exit(1);
    }
    
    if !common::global_init() {
        return;
    }
    #[cfg(all(windows, not(feature = "inline")))]
    unsafe {
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }
    if let Some(args) = crate::core_main::core_main().as_mut() {
        ui::start(args);
    }
    common::global_clean();
}

#[cfg(feature = "cli")]
fn main() {
    // 添加注册验证
    if !perform_registration_check() {
        process::exit(1);
    }
    
    if !common::global_init() {
        return;
    }
    use clap::App;
    use hbb_common::log;
    let args = format!(
        "-p, --port-forward=[PORT-FORWARD-OPTIONS] 'Format: remote-id:local-port:remote-port[:remote-host]'
        -c, --connect=[REMOTE_ID] 'test only'
        -k, --key=[KEY] ''
       -s, --server=[] 'Start server'",
    );
    let matches = App::new("rustdesk")
        .version(crate::VERSION)
        .author("Purslane Ltd")
        .about("RustDesk command line tool")
        .args_from_usage(&args)
        .get_matches();
    use hbb_common::{config::LocalConfig, env_logger::*};
    init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    if let Some(p) = matches.value_of("port-forward") {
        let options: Vec = p.split(":").map(|x| x.to_owned()).collect();
        if options.len() < 3 {
            log::error!("Wrong port-forward options");
            return;
        }
        let mut port = 0;
        if let Ok(v) = options[1].parse::() {
            port = v;
        } else {
            log::error!("Wrong local-port");
            return;
        }
        let mut remote_port = 0;
        if let Ok(v) = options[2].parse::() {
            remote_port = v;
        } else {
            log::error!("Wrong remote-port");
            return;
        }
        let mut remote_host = "localhost".to_owned();
        if options.len() > 3 {
            remote_host = options[3].clone();
        }
        common::test_rendezvous_server();
        common::test_nat_type();
        let key = matches.value_of("key").unwrap_or("").to_owned();
        let token = LocalConfig::get_option("access_token");
        cli::start_one_port_forward(
            options[0].clone(),
            port,
            remote_host,
            remote_port,
            key,
            token,
        );
    } else if let Some(p) = matches.value_of("connect") {
        common::test_rendezvous_server();
        common::test_nat_type();
        let key = matches.value_of("key").unwrap_or("").to_owned();
        let token = LocalConfig::get_option("access_token");
        cli::connect_test(p, key, token);
    } else if let Some(p) = matches.value_of("server") {
        log::info!("id={}", hbb_common::config::Config::get_id());
        crate::start_server(true, false);
    }
    common::global_clean();
}
©2025 Powered Vison
