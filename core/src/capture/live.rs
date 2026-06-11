use pcap::{Capture, Device, Packet};
use std::error::Error;

/// Провайдер захвата пакетов в реальном времени с сетевого интерфейса
pub struct Live {
    capture: Capture<pcap::Active>,
}

impl Live {
    /// Инициализирует захват пакетов с указанного сетевого интерфейса
    /// 
    /// # Arguments
    /// * `interface_name` - Имя сетевого интерфейса (e.g., "eth0", "wlan0", "wlp3s0")
    /// 
    /// # Configuration
    /// - **Promiscuous mode**: Перехватываются ВСЕ пакеты, не только адресованные хосту
    /// - **Snaplen**: 65535 байт для полного захвата пакета
    /// - **Buffer**: 16MB для предотвращения потерь при всплесках трафика
    /// - **Immediate mode**: Минимальная задержка передачи пакетов в User Space
    /// 
    /// # Returns
    /// `Ok(Live)` - успешная инициализация
    /// `Err` - интерфейс не найден или ошибка инициализации
    /// 
    /// # Example
    /// ```
    /// let mut live = Live::new("eth0")?;
    /// while let Ok(packet) = live.next_packet() {
    ///     println!("Captured {} bytes", packet.data.len());
    /// }
    /// ```
    pub fn new(interface_name: &str) -> Result<Self, Box<dyn Error>> {
        // Получаем список доступных сетевых интерфейсов
        let devices = Device::list()?;
        
        // Ищем нужный интерфейс по имени
        let device = devices
            .into_iter()
            .find(|d| d.name == interface_name)
            .ok_or_else(|| {
                // Создаём список доступных интерфейсов для вывода
                let available = Device::list()
                    .map(|devs| {
                        devs.iter()
                            .map(|d| d.name.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "Интерфейс '{}' не найден. Доступные: {:?}",
                        interface_name, available
                    ),
                )) as Box<dyn Error>
            })?;

        // Настраиваем захват с оптимальными параметрами
        let capture = Capture::from_device(device)?
            .immediate_mode(true)      // Минимизация задержек
            .snaplen(65535)             // Полный пакет (макс размер Ethernet)
            .buffer_size(16 * 1024 * 1024) // 16MB буфер
            .timeout(1000)              // Таймаут 1 сек для non-blocking поведения
            .open()?;

        println!(
            "[*] ✓ Захват пакетов инициализирован на интерфейсе: {}",
            interface_name
        );

        Ok(Self { capture })
    }

    /// Получает следующий пакет из очереди захвата
    /// 
    /// # Returns
    /// `Ok(Packet)` - успешно захвачен пакет
    /// `Err(pcap::Error)` - ошибка захвата (таймаут, ошибка интерфейса)
    pub fn next_packet(&mut self) -> Result<Packet<'_>, pcap::Error> {
        self.capture.next_packet()
    }

    /// Вспомогательный метод для получения информации об интерфейсе
    #[allow(dead_code)] // Может быть полезна в будущем
    pub fn interface_name(&self) -> Result<String, Box<dyn Error>> {
        // Это требует дополнительного доступа к метаданным pcap
        // Пока просто возвращаем пустую строку (можно расширить)
        Ok("Unknown".to_string())
    }
}