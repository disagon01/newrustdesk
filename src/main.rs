#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

// 新增：Windows 外部函数绑定
#[cfg(windows)]
extern "C" {
    fn get_machine_code() -> *const std::os::raw::c_char;
}

// 新增：依赖导入
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;
use std::ffi::CStr;
use std::process::{Command, exit};
use hex;

// 原有依赖
use librustdesk::*;

// 新增：密钥（建议通过环境变量/GitHub Secrets注入，此处为占位）
const SECRET_KEY: &str = "${{ secrets.REG_SECRET_KEY }}";

// 新增：Windows 机器码获取函数
#[cfg(windows)]
fn get_windows_machine_code() -> String {
    unsafe {
        let c_str = get_machine_code();
        if c_str.is_null() {
            "ci_fallback_12345678".to_string()
        } else {
            let rust_str = CStr::from_ptr(c_str)
                .to_str()
                .unwrap_or("ci_fallback_12345678");
            rust_str.to_string()
        }
    }
}

// 新增：Android 机器码获取占位函数（后续实现）
#[cfg(target_os = "android")]
fn get_android_machine_code() -> String {
    // 示例占位：实际需实现Android设备唯一标识获取
    "android_fallback_87654321".to_string()
}

// 新增：生成注册码
fn generate_reg_code(machine_code: &str) -> String {
    let input = format!("{}_{}", machine_code, SECRET_KEY);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result).get(0..24).unwrap_or("").to_string()
}

// 新增：检查注册状态
fn is_registered() -> bool {
    // 跨平台注册文件路径
    let reg_path = if cfg!(windows) {
        "C:\\ProgramData\\rustdesk\\registered"
    } else if cfg!(target_os = "android") {
        "/data/data/com.rustdesk/files/registered"
    } else {
        // 其他平台默认路径（如Linux/macOS）
        "/tmp/rustdesk_registered"
    };

    if Path::new(reg_path).exists() {
        let saved_reg = fs::read_to_string(reg_path).unwrap_or_default();
        let machine_code = if cfg!(windows) {
            get_windows_machine_code()
        } else if cfg!(target_os = "android") {
            get_android_machine_code()
        } else {
            // 其他平台占位
            "other_platform_fallback".to_string()
        };
        saved_reg == generate_reg_code(&machine_code)
    } else {
        false
    }
}

// 新增：注册验证弹窗（复用Flutter UI或原生弹窗）
fn show_reg_dialog() -> bool {
    #[cfg(windows)]
    {
        println!("显示注册界面...");
        let machine_code = get_windows_machine_code();
        // 方案1：调用Flutter注册界面（需确保flutter环境存在，或替换为原生Windows弹窗）
        // 注：实际生产环境建议替换为RustDesk原有Flutter UI集成，而非调用flutter命令
        let result = Command::new("flutter")
            .arg("run")
            .arg(format!("--dart-define=MACHINE_CODE={}", machine_code))
            .arg(format!("--dart-define=SECRET_KEY={}", SECRET_KEY))
            .current_dir("./flutter")
            .output();

        match result {
            Ok(output) => {
                // 假设Flutter程序退出码0表示注册成功，且已写入注册文件
                output.status.success()
            }
            Err(e) => {
                eprintln!("启动注册界面失败: {}", e);
                // 调试阶段可临时返回true，正式环境需改为false
                false
            }
        }
    }
    #[cfg(target_os = "android")]
    {
        // Android端注册界面逻辑（后续实现）
        println!("Android注册界面待实现");
        true
    }
    #[cfg(not(any(windows, target_os = "android")))]
    {
        // 其他平台默认返回true（或根据需求修改）
        true
    }
}

// 新增：注册验证入口函数
fn check_registration() {
    if !is_registered() {
        println!("未检测到有效注册，显示注册界面...");
        if !show_reg_dialog() {
            println!("注册验证失败，退出应用！");
            exit(1);
        }
    } else {
        println!("注册验证通过，启动应用...");
    }
}

// 原有：Android/iOS/Flutter分支的main函数
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
fn main() {
    // 插入注册验证
    check_registration();

    if !common::global_init() {
        return;
    }
    common::test_rendezvous_server();
    common::test_nat_type();
    common::global_clean();
}

// 原有：非移动/非CLI/非Flutter分支的main函数
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "cli",
    feature = "flutter"
)))]
fn main() {
    // 插入注册验证
    check_registration();

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

// 原有：CLI功能分支的main函数
#[cfg(feature = "cli")]
fn main() {
    // 插入注册验证（如需对CLI模式也做验证，可保留；否则注释此行）
    check_registration();

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
        .author("Purslane Ltd<info@rustdesk.com>")
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
