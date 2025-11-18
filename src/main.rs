#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use librustdesk::*;
use std::fs;
use std::path::Path;

// 密钥（实际使用时建议从环境变量或加密存储读取）
const SECRET_KEY: &str = "FUCKYOURSISTER001";

// 生成注册码（机器码+密钥哈希）
fn generate_reg_code(machine_code: &str) -> String {
    let input = format!("{}_{}", machine_code, SECRET_KEY);
    sha256::digest(input).chars().take(24).collect() // 注册码取前24位
}

// 检查是否已注册
fn is_registered() -> bool {
    // Windows：检查注册表或配置文件
    // 安卓：检查应用私有目录下的注册文件
    let reg_path = if cfg!(windows) {
        "C:\\ProgramData\\rustdesk\\registered"
    } else if cfg!(target_os = "android") {
        "/data/data/com.rustdesk/files/registered"
    } else {
        // 其他平台可添加相应路径
        return false;
    };
    
    if Path::new(reg_path).exists() {
        let saved_reg_code = fs::read_to_string(reg_path).unwrap_or_default();
        let machine_code = get_machine_code(); // 假设已实现机器码获取函数
        saved_reg_code == generate_reg_code(&machine_code)
    } else {
        false
    }
}

// 保存注册状态
fn save_registration(reg_code: &str) {
    let reg_path = if cfg!(windows) {
        "C:\\ProgramData\\rustdesk\\registered"
    } else if cfg!(target_os = "android") {
        "/data/data/com.rustdesk/files/registered"
    } else {
        return;
    };

    // 确保目录存在
    if let Some(parent) = Path::new(reg_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(reg_path, reg_code);
}

// 注册验证逻辑（抽取为共用函数）
fn perform_registration_check() -> bool {
    if is_registered() {
        return true;
    }

    let machine_code = get_machine_code();
    // 调用UI显示注册对话框（需根据实际UI框架实现）
    let user_input_reg_code = match show_registration_dialog(machine_code) {
        Some(code) => code,
        None => return false, // 用户取消
    };

    if user_input_reg_code == generate_reg_code(&machine_code) {
        save_registration(&user_input_reg_code);
        true
    } else {
        false
    }
}

// 假设的机器码获取函数（需根据实际实现替换）
fn get_machine_code() -> String {
    // 实际实现应获取硬件特征生成唯一机器码
    hbb_common::config::Config::get_id() // 临时使用现有ID作为机器码示例
}

// 假设的注册对话框函数（需根据UI框架实现）
fn show_registration_dialog(machine_code: String) -> Option<String> {
    // 实际实现应显示对话框并返回用户输入
    #[cfg(feature = "cli")]
    {
        eprintln!("请注册，机器码：{}", machine_code);
        eprintln!("请输入注册码：");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok()?;
        Some(input.trim().to_string())
    }
    #[cfg(not(feature = "cli"))]
    {
        // 图形界面实现示例（需替换为实际UI调用）
        ui::show_registration_dialog(machine_code)
    }
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
fn main() {
    // 执行注册验证
    if !perform_registration_check() {
        eprintln!("注册验证失败，退出应用");
        return;
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
    // 执行注册验证
    if !perform_registration_check() {
        eprintln!("注册验证失败，退出应用");
        return;
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
    // 执行注册验证
    if !perform_registration_check() {
        eprintln!("注册验证失败，退出应用");
        return;
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
        .author("Disvison Ltd<info@iinx.cn>")
        .about("RustDesk command line tool")
        .args_from_usage(&args)
        .get_matches();
    use hbb_common::{config::LocalConfig, env_logger::*};
    init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    if let Some(p) = matches.value_of("port-forward") {
        let options: Vec<String> = p.split(":").map(|x| x.to_owned()).collect();
        if options.len() < 3 {
            log::error!("Wrong port-forward options");
            return;
        }
        let mut port = 0;
        if let Ok(v) = options[1].parse::<i32>() {
            port = v;
        } else {
            log::error!("Wrong local-port");
            return;
        }
        let mut remote_port = 0;
        if let Ok(v) = options[2].parse::<i32>() {
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
