use pcap::{Capture, Offline, Packet};
use std::path::Path;
use std::error::Error;

#[allow(dead_code)] // Используется при тестировании
pub struct PcapReader {
    capture: Capture<Offline>,
}

#[allow(dead_code)] // Методы используются при тестировании
impl PcapReader {
    /// Инициализация чтения из .pcap файла для тестирования моделей.
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self, Box<dyn Error>> {
        // Проверка существования файла
        if !file_path.as_ref().exists() {
            return Err(format!("Файл датасета не найден: {:?}", file_path.as_ref()).into());
        }

        // Открытие файла для захвата
        let capture = Capture::from_file(file_path)?;
        
        println!("Aegis-Core: Загружен датасет для тестирования");

        Ok(Self { capture })
    }

    /// Получение следующего пакета из дампа.
    /// Позволяет имитировать поток данных для AI 1 и VAE.
    pub fn next_packet(&mut self) -> Result<Packet<'_>, pcap::Error> {
        self.capture.next_packet()
    }
}