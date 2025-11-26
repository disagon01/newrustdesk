#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use librustdesk::*;
// 授权验证所需依赖导入
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::{hmac, digest};
use sys_info::SystemInfo;
use base64::engine::{general_purpose, Engine as _};
use hex;

#[cfg(target_os = "android")]
use jni::JavaVM;
#[cfg(target_os = "android")]
use std::ptr;

// 内置密钥（需替换为自定义强密钥，建议≥32字节）
const SECRET_KEY: &[u8] = b"your_custom_32byte_secure_key_here_1234";
// 网络时间校验阈值（允许本地与网络时间偏差，单位：秒）
const TIME_DEVIATION_THRESHOLD: i64 = 300;

// 原 RustDesk 多分支 main 函数前，先执行授权校验的统一入口封装
fn main() {
    // 1. 启动时执行授权校验，未通过直接退出
    if !authorize() {
        eprintln!("授权验证失败：未注册或已过期，请联系管理员获取注册码");
        // 针对Windows图形界面程序，弹出提示框（避免后台退出无提示）
        #[cfg(target_os = "windows")]
        {
            use winapi::um::winuser::{MessageBoxA, MB_ICONERROR, MB_OK};
            unsafe {
                MessageBoxA(
                    std::ptr::null_mut(),
                    b"授权验证失败：未注册或已过期，请联系管理员获取注册码\0".as_ptr() as _,
                    b"RustDesk 授权错误\0".as_ptr() as _,
                    MB_OK | MB_ICONERROR,
                );
            }
        }
        exit(1);
    }

    // 2. 执行原 RustDesk 的核心逻辑分支
    original_main();
}

/// 原 RustDesk 的多分支 main 函数逻辑（完整保留）
fn original_main() {
    #[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
    {
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
    {
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
    {
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
}

/// 完整授权校验流程
fn authorize() -> bool {
    // 2. 生成设备唯一机器码
    let machine_code = match generate_machine_code() {
        Ok(code) => code,
        Err(_) => {
            #[cfg(target_os = "windows")]
            unsafe {
                use winapi::um::winuser::{MessageBoxA, MB_ICONERROR, MB_OK};
                MessageBoxA(
                    std::ptr::null_mut(),
                    b"无法生成设备机器码，请检查系统权限\0".as_ptr() as _,
                    b"RustDesk 授权错误\0".as_ptr() as _,
                    MB_OK | MB_ICONERROR,
                );
            }
            return false;
        }
    };

    // 3. 读取用户输入的注册码（优化：优先从配置文件读取，其次命令行）
    let user_reg_code = match read_reg_code() {
        Ok(code) => code,
        Err(_) => {
            #[cfg(target_os = "windows")]
            unsafe {
                use winapi::um::winuser::{MessageBoxA, MB_ICONWARNING, MB_OK};
                MessageBoxA(
                    std::ptr::null_mut(),
                    b"未检测到注册码，请通过命令行传入或写入reg.code文件\0".as_ptr() as _,
                    b"RustDesk 授权提示\0".as_ptr() as _,
                    MB_OK | MB_ICONWARNING,
                );
            }
            return false;
        }
    };

    // 4. 校验注册码有效性（机器码+时间戳匹配）
    verify_reg_code(&machine_code, &user_reg_code)
}

/// 生成设备唯一机器码（Windows/Android 差异化实现，补充Linux/macOS适配）
fn generate_machine_code() -> Result<String, ()> {
    #[cfg(target_os = "windows")]
    {
        // Windows：读取主板UUID（通过sys-info库）
        let sys_info = sys_info::get_info().map_err(|_| ())?;
        let motherboard_uuid = sys_info.board.as_ref().ok_or(())?.uuid.as_ref().ok_or(())?;
        // 哈希处理为固定长度机器码（SHA-256）
        let hash = digest::digest(&digest::SHA256, motherboard_uuid.as_bytes());
        Ok(hex::encode(hash))
    }

    #[cfg(target_os = "android")]
    {
        // Android：读取Android ID（通过JNI调用系统API）
        let android_id = get_android_id().map_err(|_| ())?;
        let hash = digest::digest(&digest::SHA256, android_id.as_bytes());
        Ok(hex::encode(hash))
    }

    #[cfg(target_os = "linux")]
    {
        // Linux：读取/etc/machine-id（系统唯一标识）
        let machine_id = std::fs::read_to_string("/etc/machine-id").map_err(|_| ())?;
        let hash = digest::digest(&digest::SHA256, machine_id.trim().as_bytes());
        Ok(hex::encode(hash))
    }

    #[cfg(target_os = "macos")]
    {
        // macOS：读取IOPlatformUUID（硬件唯一标识）
        use std::process::Command;
        let output = Command::new("ioreg")
            .args(&["-d2", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|_| ())?;
        let output_str = String::from_utf8(output.stdout).map_err(|_| ())?;
        let uuid = output_str
            .lines()
            .find(|l| l.contains("IOPlatformUUID"))
            .map(|l| l.split("=").nth(1).unwrap().trim().replace('"', ""))
            .ok_or(())?;
        let hash = digest::digest(&digest::SHA256, uuid.as_bytes());
        Ok(hex::encode(hash))
    }

    #[cfg(not(any(target_os = "windows", target_os = "android", target_os = "linux", target_os = "macos")))]
    {
        // 其他平台暂不支持
        Err(())
    }
}

/// Android 平台获取 Android ID（JNI调用）
#[cfg(target_os = "android")]
fn get_android_id() -> Result<String, ()> {
    let vm = JavaVM::from_raw(unsafe { jni::sys::JavaVM::default() }).map_err(|_| ())?;
    let env = vm.attach_current_thread().map_err(|_| ())?;
    let context = env.find_class("android/content/Context").map_err(|_| ())?;
    let activity_thread = env.find_class("android/app/ActivityThread").map_err(|_| ())?;
    let current_app = env.call_static_method(
        activity_thread,
        "currentApplication",
        "()Landroid/app/Application;",
        &[],
    ).map_err(|_| ())?.l().map_err(|_| ())?;
    let content_resolver = env.call_method(
        current_app,
        "getContentResolver",
        "()Landroid/content/ContentResolver;",
        &[],
    ).map_err(|_| ())?.l().map_err(|_| ())?;
    let settings_secure = env.find_class("android/provider/Settings$Secure").map_err(|_| ())?;
    let android_id = env.call_static_method(
        settings_secure,
        "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
        &[
            content_resolver.into(),
            env.new_string("android_id").map_err(|_| ())?.into()
        ],
    ).map_err(|_| ())?.l().map_err(|_| ())?;
    let android_id_str = env.get_string(android_id.into()).map_err(|_| ())?.into();
    Ok(android_id_str)
}

/// 读取用户注册码（优化：优先从配置文件读取，其次命令行）
fn read_reg_code() -> Result<String, ()> {
    // 优先从程序同目录的reg.code文件读取注册码
    let reg_code_path = std::env::current_exe()
        .map_err(|_| ())?
        .parent()
        .ok_or(())?
        .join("reg.code");
    if std::fs::exists(&reg_code_path).map_err(|_| ())? {
        let code = std::fs::read_to_string(&reg_code_path).map_err(|_| ())?;
        let trimmed_code = code.trim();
        if !trimmed_code.is_empty() {
            return Ok(trimmed_code.to_string());
        }
    }

    // 配置文件无注册码时，从命令行参数读取
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(());
    }
    Ok(args[1].trim().to_string())
}

/// 校验注册码（机器码+密钥+有效期时间戳匹配）
fn verify_reg_code(machine_code: &str, reg_code: &str) -> bool {
    // 解码注册码（Base64）
    let decoded = match general_purpose::STANDARD.decode(reg_code) {
        Ok(d) => d,
        Err(_) => return false,
    };
    // 拆分：前64字节为HMAC签名，后8字节为有效期时间戳（Unix秒）
    if decoded.len() != 64 + 8 {
        return false;
    }
    let (signature, timestamp_bytes) = decoded.split_at(64);
    let expire_timestamp = match i64::from_be_bytes(timestamp_bytes.try_into().unwrap()) {
        t => t,
    };

    // 校验时间（本地时间+网络时间双重验证）
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if current_time > expire_timestamp {
        return false; // 本地时间已过期
    }
    // 网络时间校验（防篡改系统时间）
    match get_ntp_time() {
        Ok(ntp_time) => {
            if ntp_time > expire_timestamp || (current_time - ntp_time).abs() > TIME_DEVIATION_THRESHOLD {
                return false;
            }
        }
        Err(_) => {
            // 网络时间获取失败时，可选择宽松模式（仅本地时间）或严格模式（拒绝）
            // 此处改为宽松模式，如需严格则返回false
            // return false;
        }
    }

    // 校验HMAC签名（机器码+时间戳+密钥）
    let sign_data = format!("{}{}", machine_code, expire_timestamp);
    let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET_KEY);
    hmac::verify(&key, sign_data.as_bytes(), signature).is_ok()
}

/// 获取网络时间（NTP服务器：time.windows.com，补充备用服务器）
fn get_ntp_time() -> Result<i64, ()> {
    let ntp_servers = &["time.windows.com:123", "pool.ntp.org:123", "time.google.com:123"];
    for &server in ntp_servers {
        match get_ntp_time_from_server(server) {
            Ok(t) => return Ok(t),
            Err(_) => continue,
        }
    }
    Err(())
}

/// 从单个NTP服务器获取时间
fn get_ntp_time_from_server(server: &str) -> Result<i64, ()> {
    let mut socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|_| ())?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3))).map_err(|_| ())?;
    // 发送NTP请求（简化版NTP协议）
    let mut request = [0u8; 48];
    request[0] = 0x1B; // NTP版本3，客户端模式
    socket.send_to(&request, server).map_err(|_| ())?;
    // 接收响应
    let mut response = [0u8; 48];
    let (_, _) = socket.recv_from(&mut response).map_err(|_| ())?;
    // 解析NTP时间（转换为Unix时间戳）
    let ntp_time = u64::from_be_bytes(response[40..48].try_into().unwrap());
    let unix_time = ntp_time - 2208988800; // NTP起始时间（1900年）转Unix起始时间（1970年）
    Ok(unix_time as i64)
}
