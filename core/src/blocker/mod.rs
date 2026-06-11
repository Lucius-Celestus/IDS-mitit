use std::collections::HashSet;
use std::sync::Mutex;
use std::process::Command;
use lazy_static::lazy_static;

lazy_static! {
    /// Глобальный реестр заблокированных IP адресов в памяти
    static ref BLACKLIST: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

/// Проверяет находимся ли мы в Production режиме блокировки
fn is_production_mode() -> bool {
    std::env::var("BLOCK_MODE")
        .unwrap_or_else(|_| "shadow".to_string())
        .to_lowercase() == "production"
}

/// Блокирует IP адрес через iptables (требует root privileges)
/// 
/// # Arguments
/// * `ip` - IP адрес для блокировки (IPv4 или IPv6)
/// 
/// # Errors
/// Логирует ошибки, но не паникует для устойчивости системы
#[allow(dead_code)] // Используется в production mode
pub fn block_ip(ip: &str) {
    // В Shadow Mode только логируем, не блокируем
    if !is_production_mode() {
        println!("[SHADOW] 🎭 Режим логирования (не блокируем): IP {} был бы заблокирован", ip);
        return;
    }
    // Валидация IP адреса (простая проверка)
    if !is_valid_ip(ip) {
        eprintln!("[!] Невалидный IP адрес: {}", ip);
        return;
    }

    let mut blacklist = match BLACKLIST.lock() {
        Ok(bl) => bl,
        Err(e) => {
            eprintln!("[!] Ошибка получения доступа к blacklist: {}", e);
            return;
        }
    };

    // Проверяем, не заблокирован ли уже этот IP
    if blacklist.contains(ip) {
        return; // Уже в списке, ничего не делаем
    }

    eprintln!("[BLOCK] 🔒 Блокировка IP: {}", ip);

    // Вызов iptables для DROP пакетов от источника
    match Command::new("iptables")
        .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                blacklist.insert(ip.to_string());
                println!("[✓] IP {} успешно заблокирован", ip);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("[!] Ошибка iptables: {}", stderr);
            }
        }
        Err(e) => {
            eprintln!("[!] Ошибка выполнения iptables: {}", e);
            eprintln!("    (возможно, требуются root права или iptables не установлен)");
        }
    }
}

/// Проверяет валидность IP адреса (простая проверка)
#[allow(dead_code)] // Вспомогательная функция
fn is_valid_ip(ip: &str) -> bool {
    // IPv4: проверка четырёх октетов
    let ipv4_parts: Vec<&str> = ip.split('.').collect();
    if ipv4_parts.len() == 4 {
        return ipv4_parts.iter().all(|part| {
            part.parse::<u8>().is_ok()
        });
    }

    // IPv6: содержит двоеточие
    if ip.contains(':') && ip.contains(|c: char| c.is_ascii_hexdigit() || c == ':') {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("127.0.0.1"));
        assert!(is_valid_ip("255.255.255.255"));
    }

    #[test]
    fn test_invalid_ipv4() {
        assert!(!is_valid_ip("256.1.1.1"));
        assert!(!is_valid_ip("1.1.1"));
        assert!(!is_valid_ip("not-an-ip"));
    }

    #[test]
    fn test_valid_ipv6() {
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));
    }
}