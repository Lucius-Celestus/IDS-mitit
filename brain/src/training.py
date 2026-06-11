"""
Система дообучения модели AEGIS-NDR с отслеживанием метрик точности
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix


class ModelTrainer:
    """Система переобучения модели AEGIS с отслеживанием метрик"""
    
    def __init__(self, 
                 feedback_path="/app/data/logs/feedback.jsonl",
                 metrics_path="/app/data/logs/metrics.json",
                 model_path="/app/data/knowledge/ai1_model.pkl",
                 min_samples=10,
                 cv_folds=5):
        """
        Инициализация тренера модели
        
        Args:
            feedback_path: Путь к файлу feedback'ов
            metrics_path: Путь к файлу метрик
            model_path: Путь к сохраненной модели
            min_samples: Минимальное количество примеров для переобучения
            cv_folds: Количество fold'ов для крос-валидации
        """
        self.feedback_path = feedback_path
        self.metrics_path = metrics_path
        self.model_path = model_path
        self.min_samples = min_samples
        self.cv_folds = cv_folds
        
        # Особенности, которые ожидает модель (совпадают с Core/Brain)
        self.features = ['packet_len', 'iat', 'entropy', 'tcp_flags']
        
        # Загрузить текущую модель или создать новую
        self.model = self._load_or_init_model()
        self.scaler = StandardScaler()
        
        # Загрузить текущие метрики
        self.metrics_history = self._load_metrics_history()
        
        print("[+] ModelTrainer инициализирован")
        print(f"    Feedback: {feedback_path}")
        print(f"    Метрики: {metrics_path}")
        print(f"    Модель: {model_path}")
    
    def _load_or_init_model(self) -> RandomForestClassifier:
        """Загрузить модель или создать новую"""
        if os.path.exists(self.model_path):
            try:
                print(f"[+] Загрузка модели из {self.model_path}")
                model = joblib.load(self.model_path)
                return model
            except Exception as e:
                print(f"[!] Ошибка загрузки модели: {e}")
        
        print("[*] Создание новой модели RandomForestClassifier")
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'  # Для работы с несбалансированными данными
        )
    
    def _load_metrics_history(self) -> List[Dict]:
        """Загрузить историю метрик"""
        if os.path.exists(self.metrics_path):
            try:
                with open(self.metrics_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Ошибка загрузки метрик: {e}")
        
        return []
    
    def collect_feedback(self) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], List[str]]:
        """
        Собрать feedback'и из файла
        
        Returns:
            (X, y, processed_ids) - признаки, метки и IDs обработанных feedback'ов
            или (None, None, []) если недостаточно данных
        """
        os.makedirs(os.path.dirname(self.feedback_path) or '.', exist_ok=True)
        
        if not os.path.exists(self.feedback_path):
            print(f"[!] Файл feedback'ов не найден: {self.feedback_path}")
            return None, None, []
        
        feedbacks = []
        processed_ids = []
        
        try:
            with open(self.feedback_path, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        # Пропустить если уже обработано
                        if entry.get('_used', False):
                            continue
                        feedbacks.append(entry)
                        processed_ids.append(entry.get('id', str(len(feedbacks))))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[!] Ошибка чтения feedback'ов: {e}")
            return None, None, []
        
        if not feedbacks:
            print("[*] Нет новых feedback'ов")
            return None, None, []
        
        # Преобразовать в DataFrame для удобства
        df = pd.DataFrame(feedbacks)
        
        # Проверить наличие нужных столбцов
        if 'verdict' not in df.columns or 'features' not in df.columns:
            print("[!] Неверная структура feedback'ов (нужны 'verdict' и 'features')")
            return None, None, []
        
        # Проверить минимальное количество примеров
        if len(df) < self.min_samples:
            print(f"[!] Недостаточно примеров: {len(df)} (минимум {self.min_samples})")
            return None, None, []
        
        # Проверить наличие обоих классов
        class_counts = df['verdict'].value_counts()
        if len(class_counts) < 2:
            print(f"[!] Нужны оба класса (атака/нормальный), найдены: {class_counts.to_dict()}")
            return None, None, []
        
        # Извлечь признаки
        X_list = []
        y_list = []
        
        for idx, row in df.iterrows():
            try:
                features = row['features']
                
                # Если features - строка JSON, распарсить ее
                if isinstance(features, str):
                    features = json.loads(features)
                
                # Извлечь значения признаков в нужном порядке
                x_row = np.array([
                    float(features.get(f, 0.0)) for f in self.features
                ])
                
                X_list.append(x_row)
                
                # Преобразовать verdict в бинарную метку: 0=benign, 1=attack
                verdict = row['verdict'].lower()
                y = 1 if 'attack' in verdict or 'malicious' in verdict or verdict == '1' else 0
                y_list.append(y)
                
            except Exception as e:
                print(f"[!] Ошибка парсинга feedback #{idx}: {e}")
                continue
        
        if not X_list or not y_list:
            print("[!] Не удалось парсить feedback'и")
            return None, None, []
        
        X = np.array(X_list)
        y = np.array(y_list)
        
        print(f"[+] Собрано {len(X)} feedback'ов:")
        print(f"    - Нормальные: {np.sum(y == 0)}")
        print(f"    - Атаки: {np.sum(y == 1)}")
        
        return X, y, processed_ids
    
    def retrain(self, force=False) -> Dict:
        """
        Переобучить модель на собранных feedback'ах
        
        Args:
            force: Сохранить модель даже если F1 не улучшился
            
        Returns:
            Словарь с результатами переобучения
        """
        print("\n" + "=" * 60)
        print("[*] НАЧАЛО ПЕРЕОБУЧЕНИЯ МОДЕЛИ")
        print("=" * 60)
        
        # Собрать feedback
        X, y, processed_ids = self.collect_feedback()
        
        if X is None:
            print("[!] Переобучение отменено: недостаточно данных")
            return {'success': False, 'reason': 'insufficient_data'}
        
        # Нормализовать признаки
        X_scaled = self.scaler.fit_transform(X)
        
        # Вычислить метрики через крос-валидацию
        cv_strategy = StratifiedKFold(n_splits=self.cv_folds, shuffle=True, random_state=42)
        
        print(f"\n[*] Запуск {self.cv_folds}-fold кросс-валидации...")
        
        f1_scores = cross_val_score(
            self.model, X_scaled, y, 
            cv=cv_strategy, 
            scoring='f1_weighted'
        )
        
        precision_scores = cross_val_score(
            self.model, X_scaled, y,
            cv=cv_strategy,
            scoring='precision_weighted'
        )
        
        recall_scores = cross_val_score(
            self.model, X_scaled, y,
            cv=cv_strategy,
            scoring='recall_weighted'
        )
        
        # Средние значения
        avg_f1 = f1_scores.mean()
        avg_precision = precision_scores.mean()
        avg_recall = recall_scores.mean()
        
        # Стандартные отклонения
        std_f1 = f1_scores.std()
        std_precision = precision_scores.std()
        std_recall = recall_scores.std()
        
        print(f"\n[*] Результаты кросс-валидации:")
        print(f"    F1-Score: {avg_f1:.4f} (±{std_f1:.4f})")
        print(f"    Precision: {avg_precision:.4f} (±{std_precision:.4f})")
        print(f"    Recall: {avg_recall:.4f} (±{std_recall:.4f})")
        
        # Получить лучшую предыдущую F1
        best_prev_f1 = max(
            [m.get('f1', 0) for m in self.metrics_history],
            default=0
        )
        
        print(f"\n[*] Лучшая F1 из истории: {best_prev_f1:.4f}")
        
        # Переобучить модель на всех данных
        print(f"\n[*] Переобучение модели на всех {len(X)} примерах...")
        self.model.fit(X_scaled, y)
        
        # Проверить нужно ли сохранять модель
        should_save = force or avg_f1 > best_prev_f1
        
        if should_save:
            print(f"[+] F1 улучшился! Сохранение модели...")
            os.makedirs(os.path.dirname(self.model_path) or '.', exist_ok=True)
            joblib.dump(self.model, self.model_path)
            print(f"[+] Модель сохранена: {self.model_path}")
        else:
            print(f"[!] F1 не улучшился (текущая: {avg_f1:.4f}, лучшая: {best_prev_f1:.4f})")
            print(f"[*] Модель не сохранена")
        
        # Сохранить метрики
        metric_entry = {
            'timestamp': datetime.now().isoformat(),
            'f1': float(avg_f1),
            'f1_std': float(std_f1),
            'precision': float(avg_precision),
            'precision_std': float(std_precision),
            'recall': float(avg_recall),
            'recall_std': float(std_recall),
            'samples': int(len(X)),
            'benign': int(np.sum(y == 0)),
            'attacks': int(np.sum(y == 1)),
            'cv_folds': self.cv_folds,
            'model_saved': should_save,
            'improvement': float(avg_f1 - best_prev_f1)
        }
        
        self.metrics_history.append(metric_entry)
        self._save_metrics()
        
        # Пометить feedback'и как использованные
        self._mark_feedback_used(processed_ids)
        
        print(f"\n[+] Метрики сохранены")
        print(f"[+] {len(processed_ids)} feedback'ов помечены как использованные")
        print("=" * 60 + "\n")
        
        return {
            'success': True,
            'f1': float(avg_f1),
            'precision': float(avg_precision),
            'recall': float(avg_recall),
            'samples': int(len(X)),
            'model_saved': should_save
        }
    
    def get_metrics(self) -> Dict:
        """
        Получить текущие метрики
        
        Returns:
            Словарь с последними метриками и историей
        """
        if not self.metrics_history:
            return {
                'current': None,
                'history': [],
                'best_f1': 0,
                'best_timestamp': None
            }
        
        current = self.metrics_history[-1]
        
        # Найти лучшую F1 за всю историю
        best_entry = max(self.metrics_history, key=lambda x: x.get('f1', 0))
        
        return {
            'current': current,
            'history': self.metrics_history[-20:],  # Последние 20 записей
            'best_f1': best_entry['f1'],
            'best_timestamp': best_entry['timestamp'],
            'total_evaluations': len(self.metrics_history)
        }
    
    def _mark_feedback_used(self, feedback_ids: List[str]):
        """
        Пометить feedback'и как использованные
        
        Args:
            feedback_ids: Список ID feedback'ов для пометки
        """
        if not os.path.exists(self.feedback_path):
            return
        
        try:
            # Читать все feedback'и
            feedbacks = []
            with open(self.feedback_path, 'r') as f:
                for line in f:
                    if line.strip():
                        feedbacks.append(json.loads(line))
            
            # Пометить использованные
            for entry in feedbacks:
                if entry.get('id', str(feedbacks.index(entry))) in feedback_ids:
                    entry['_used'] = True
            
            # Переписать файл
            with open(self.feedback_path, 'w') as f:
                for entry in feedbacks:
                    f.write(json.dumps(entry) + '\n')
                    
        except Exception as e:
            print(f"[!] Ошибка пометки feedback'ов: {e}")
    
    def _save_metrics(self):
        """Сохранить метрики в файл"""
        try:
            os.makedirs(os.path.dirname(self.metrics_path) or '.', exist_ok=True)
            with open(self.metrics_path, 'w') as f:
                json.dump(self.metrics_history, f, indent=2)
        except Exception as e:
            print(f"[!] Ошибка сохранения метрик: {e}")


def main():
    """Точка входа для запуска из контейнера"""
    print("\n" + "=" * 60)
    print("AEGIS-NDR МОДЕЛЬ ПЕРЕОБУЧЕНИЯ")
    print("=" * 60)
    
    trainer = ModelTrainer()
    result = trainer.retrain()
    
    if result['success']:
        print(f"\n[✓] Переобучение успешно завершено")
        print(f"    F1-Score: {result['f1']:.4f}")
        print(f"    Precision: {result['precision']:.4f}")
        print(f"    Recall: {result['recall']:.4f}")
        print(f"    Примеров использовано: {result['samples']}")
        print(f"    Модель сохранена: {result['model_saved']}")
    else:
        print(f"\n[✗] Переобучение не требуется: {result['reason']}")


if __name__ == "__main__":
    main()
