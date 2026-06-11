import numpy as np
import logging
from typing import Dict, Tuple, Optional
from pathlib import Path
import joblib

# Настройка логгера для проф. отладки
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Aegis-Isomorphic")

class IsomorphicEngine:
    def __init__(self, knowledge_base_path: str):
        self.kb_path = Path(knowledge_base_path)
        self.kb: Dict[str, np.ndarray] = self._load_knowledge()
        
        # Кэшируем нормы векторов из базы, чтобы не считать их каждый раз
        self.kb_names = list(self.kb.keys())
        if self.kb:
            self.kb_matrix = np.array(list(self.kb.values()))
            self.kb_norms = np.linalg.norm(self.kb_matrix, axis=1)
        else:
            self.kb_matrix = np.empty((0, 0))
            self.kb_norms = np.empty(0)

    def _load_knowledge(self) -> Dict[str, np.ndarray]:
        """Загрузка базы скелетов с проверкой пути."""
        if not self.kb_path.exists():
            logger.warning(f"Knowledge base not found at {self.kb_path}. Using empty KB.")
            return {}
        try:
            return joblib.load(self.kb_path)
        except Exception as e:
            logger.error(f"Failed to load KB: {e}")
            return {}

    def find_invariant(self, current_vector: np.ndarray, threshold: float = 0.85) -> Tuple[Optional[str], float]:
        """
        Векторизованный поиск инварианта. Быстрее циклов в десятки раз.
        """
        if self.kb_matrix.size == 0:
            return None, 0.0

        # Считаем норму текущего вектора
        current_norm = np.linalg.norm(current_vector)
        if current_norm < 1e-9:
            return None, 0.0

        # Векторизованное косинусное сходство: (A @ B_T) / (|A| * |B_all|)
        dot_products = np.dot(self.kb_matrix, current_vector)
        similarities = dot_products / (self.kb_norms * current_norm)

        # Находим лучший результат
        best_idx = np.argmax(similarities)
        max_similarity = similarities[best_idx]

        if max_similarity >= threshold:
            return self.kb_names[best_idx], float(max_similarity)
        
        return None, float(max_similarity)

    @staticmethod
    def _calculate_similarity(g1: np.ndarray, g2: np.ndarray) -> float:
        """Fallback метод для одиночного сравнения с защитой от ZeroDivision."""
        norm_prod = np.linalg.norm(g1) * np.linalg.norm(g2)
        if norm_prod < 1e-9:
            return 0.0
        return float(np.dot(g1, g2) / norm_prod)