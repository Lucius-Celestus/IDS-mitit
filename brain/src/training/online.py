import os
import glob
import torch
import joblib
import random
import pandas as pd
import numpy as np
import torch.optim as optim
from river import forest, preprocessing
from datetime import datetime
from vae.model import AegisVAE


class OnlineTrainer:
    """Система онлайн-обучения для моделей AEGIS с адаптацией к реальному трафику"""
    
    def __init__(self, 
                 ai1_path="/app/data/knowledge/ai1_model.pkl", 
                 ai2_path="/app/data/knowledge/ai2_model.pth"):
        self.ai1_path = ai1_path
        self.ai2_path = ai2_path
        
        # Единый стандарт Aegis (Core Rust Format)
        self.features = ['packet_len', 'iat', 'entropy', 'tcp_flags', 'dest_port']
        
        # Карта перевода: "Внешний мир" (CIC-IDS) -> "Внутренний мир" (Aegis)
        self.rename_map = {
            'Dst Port': 'dest_port',
            'Pkt Len Mean': 'packet_len',
            'Flow IAT Mean': 'iat',
            'PSH Flag Cnt': 'tcp_flags'
        }
        
        # 1. Инициализация AI1 (River ARFClassifier)
        self.model_ai1 = self._load_or_init_ai1()
        
        # 2. Инициализация AI2 (Torch VAE)
        self.model_ai2 = AegisVAE(input_dim=len(self.features))
        self.ai2_optimizer = optim.Adam(self.model_ai2.parameters(), lr=1e-4)
        self._load_ai2()
        
        # Статистика обучения
        self.training_stats = {
            'total_learned': 0,
            'attacks_learned': 0,
            'benign_learned': 0,
            'last_update': datetime.now().isoformat()
        }

    def _load_or_init_ai1(self):
        """Загрузить или создать новую модель AI1"""
        if os.path.exists(self.ai1_path):
            print(f"[+] Загрузка AI1 из {self.ai1_path}")
            return joblib.load(self.ai1_path)
        
        print("[*] Создание новой AI1 модели (ARFClassifier + StandardScaler)")
        # StandardScaler - нормализует признаки перед классификацией
        return preprocessing.StandardScaler() | forest.ARFClassifier(
            n_models=3,        # 3 деревья в лесе
            max_depth=25,      # Максимальная глубина дерева
            lambda_value=0.01  # Параметр распада старых данных
        )

    def _load_ai2(self):
        """Загрузить или создать новую модель AI2 (VAE)"""
        if os.path.exists(self.ai2_path):
            print(f"[+] Загрузка AI2 из {self.ai2_path}")
            self.model_ai2.load_state_dict(torch.load(self.ai2_path))
        
        self.model_ai2.train()

    def learn_one(self, features_dict: dict, label: int, save_periodic=True):
        """
        Онлайн обучение на одном пакете
        
        Args:
            features_dict: Словарь признаков {'packet_len': X, 'iat': X, ...}
            label: 0=benign, 1=attack
            save_periodic: Сохранять ли модели периодически
        """
        
        # AI1 учится на обоих классах (классификатор)
        self.model_ai1.learn_one(features_dict, label)
        
        # AI2 (VAE) учится ТОЛЬКО на нормальном трафике
        if label == 0:
            self._train_vae_one(features_dict)
        
        # Обновяем статистику
        self.training_stats['total_learned'] += 1
        if label == 1:
            self.training_stats['attacks_learned'] += 1
        else:
            self.training_stats['benign_learned'] += 1
        self.training_stats['last_update'] = datetime.now().isoformat()
        
        # Периодическое сохранение
        if save_periodic and self.training_stats['total_learned'] % 100 == 0:
            self.save_models()
            print(
                f"[*] Checkpoint: {self.training_stats['total_learned']} пакетов "
                f"({self.training_stats['attacks_learned']} атак, "
                f"{self.training_stats['benign_learned']} норма)",
                flush=True
            )

    def _train_vae_one(self, features_dict: dict):
        """Обучить VAE на одном примере нормального трафика"""
        try:
            # Преобразуем в tensor
            values = [features_dict.get(f, 0.0) for f in self.features]
            tensor_x = torch.FloatTensor([values]).unsqueeze(1)  # (1, 1, 5)
            
            # Forward pass
            recon_x, mu, logvar = self.model_ai2(tensor_x)
            
            # Расчет loss
            loss = self.model_ai2.get_loss(recon_x, tensor_x, mu, logvar)
            
            # Backprop
            self.ai2_optimizer.zero_grad()
            loss.backward()
            self.ai2_optimizer.step()
            
        except Exception as e:
            print(f"[!] Ошибка обучения VAE: {e}", flush=True)

    def train_batch(self, dataset_path: str):
        """
        Батч-обучение на датасете
        
        Args:
            dataset_path: Путь до CSV файла с датасетом
        """
        print(f"[*] Начало батч-обучения на {dataset_path}")
        
        try:
            # Читаем данные
            df = pd.read_csv(dataset_path, low_memory=False)
            
            # Гармонизируем колонки
            df = df.rename(columns=self.rename_map)
            
            total_samples = len(df)
            processed = 0
            
            for idx, row in df.iterrows():
                try:
                    # Извлекаем признаки
                    features = {
                        'packet_len': float(row.get('packet_len', 0)),
                        'iat': float(row.get('iat', 0.001)),
                        'entropy': float(row.get('entropy', 4.0)),
                        'tcp_flags': int(row.get('tcp_flags', 0)),
                        'dest_port': int(row.get('dest_port', 0))
                    }
                    
                    # Определяем метку (0=norma, 1=ataka)
                    label_col = row.get('Label') or row.get('label') or row.get('Class')
                    label = 0 if label_col == 'BENIGN' or label_col == 0 else 1
                    
                    # Обучаем
                    self.learn_one(features, label, save_periodic=True)
                    
                    processed += 1
                    if processed % 1000 == 0:
                        print(f"  > Обработано {processed}/{total_samples}", flush=True)
                        
                except Exception as e:
                    print(f"[!] Ошибка обработки строки {idx}: {e}", flush=True)
                    continue
            
            print(f"[+] Батч-обучение завершено: {processed} образцов", flush=True)
            self.save_models()
            
        except Exception as e:
            print(f"[!] Ошибка при чтении датасета: {e}", flush=True)

    def train_balanced(self, directory_path: str):
        """
        Сбалансированное обучение на папке датасетов с гармонизацией
        """
        print(f"[*] Начало сбалансированного обучения из {directory_path}")
        
        all_files = glob.glob(os.path.join(directory_path, "*.csv"))
        attack_files = [f for f in all_files if "benign" not in f.lower()]
        benign_files = [f for f in all_files if "benign" in f.lower()]

        if not benign_files:
            print("[!] ОШИБКА: Нет файла мирного трафика. Калибровка прервана.")
            return

        print(f"[*] Найдено: {len(attack_files)} файлов атак, {len(benign_files)} файлов норма")

        # Загрузим мирный трафик
        benign_samples = []
        for benign_file in benign_files:
            print(f"  > Загруз норм: {os.path.basename(benign_file)}")
            try:
                df_benign = pd.read_csv(benign_file, low_memory=False)
                df_benign = df_benign.rename(columns=self.rename_map)
                benign_samples.extend(df_benign[self.features].to_dict(orient='records'))
            except Exception as e:
                print(f"[!] Ошибка: {e}")
        
        random.shuffle(benign_samples)
        print(f"[+] Загружено {len(benign_samples)} образцов нормального трафика")

        # Обучаем на атаках с примешиванием нормы
        for atk_file in attack_files:
            print(f"  > Обучение на: {os.path.basename(atk_file)}")
            
            try:
                for chunk in pd.read_csv(atk_file, chunksize=500, low_memory=False):
                    chunk = chunk.rename(columns=self.rename_map)
                    
                    # Инъекция энтропии для датасетов без неё
                    if 'entropy' not in chunk.columns:
                        chunk['entropy'] = np.random.normal(4.5, 1.5, len(chunk))
                    
                    # Обучаем на атаках
                    for idx, row in chunk.iterrows():
                        try:
                            features = self._extract_features(row)
                            self.learn_one(features, label=1)
                        except:
                            pass
                    
                    # Примешиваем нормальный трафик для баланса
                    benign_batch = random.sample(benign_samples, min(len(chunk)//2, len(benign_samples)))
                    for sample in benign_batch:
                        self.learn_one(sample, label=0)
                        
            except Exception as e:
                print(f"[!] Ошибка обработки {atk_file}: {e}")
        
        print("[+] Сбалансированное обучение завершено")
        self.save_models()

    def _extract_features(self, row) -> dict:
        """Безопасное извлечение признаков из строки датасета"""
        return {
            'packet_len': float(row.get('packet_len', 0)),
            'iat': float(row.get('iat', 0.001)),
            'entropy': float(row.get('entropy', 4.0)),
            'tcp_flags': int(row.get('tcp_flags', 0)),
            'dest_port': int(row.get('dest_port', 0))
        }

    def save_models(self):
        """Сохранить обе модели на диск"""
        try:
            joblib.dump(self.model_ai1, self.ai1_path)
            torch.save(self.model_ai2.state_dict(), self.ai2_path)
            print(f"[+] Модели сохранены (AI1: {self.ai1_path}, AI2: {self.ai2_path})", flush=True)
        except Exception as e:
            print(f"[!] Ошибка сохранения: {e}", flush=True)

    def get_statistics(self) -> dict:
        """Получить статистику обучения"""
        return {
            **self.training_stats,
            'ai1_type': str(type(self.model_ai1)),
            'ai2_status': 'trained' if self.model_ai2.state_dict() else 'untrained'
        }

                
                # 3. Фильтрация и перехват KeyError
                try:
                    X_atk = chunk[self.features].to_dict(orient='records')
                except KeyError as e:
                    # Если структура совсем битая, пропускаем чанк, чтобы не ронять скрипт
                    print(f"    [!] Пропуск чанка (нет колонки): {e}")
                    continue

                # --- ЭТАП БАЛАНСИРОВКИ ---
                for xi_atk in X_atk:
                    # Учим атаку
                    self.update_on_the_fly(xi_atk, label=1)
                    
                    # СРАЗУ учим норму (создаем пропорцию 50/50 в сознании модели)
                    xi_benign = benign_samples[b_idx % total_b]
                    self.update_on_the_fly(xi_benign, label=0)
                    b_idx += 1

        self.save_all()

    def save_all(self):
        """Дамп весов на жесткий диск."""
        os.makedirs(os.path.dirname(self.ai1_path), exist_ok=True)
        joblib.dump(self.model_ai1, self.ai1_path)
        torch.save(self.model_ai2.state_dict(), self.ai2_path)
        print(f"[{datetime.now()}] Калибровка завершена. Резервная копия базы знаний создана.")

if __name__ == "__main__":
    trainer = OnlineTrainer()
    trainer.train_balanced("/app/data/datasets")