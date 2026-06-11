import torch
import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix
from vae.model import AegisVAE
from ai2.transformer import AegisTransformer

class AegisValidator:
    def __init__(self, data_path="/app/data/datasets/base_eval.csv"):
        self.data_path = data_path
        # Загрузка весов из "Базы Знаний" [cite: 89, 121, 161]
        self.ai1 = joblib.load("/app/data/knowledge/ai1_model.pkl")
        
        self.vae = AegisVAE(input_dim=16)
        self.vae.load_state_dict(torch.load("/app/data/knowledge/vae.pth"))
        self.vae.eval()
        
        self.ai2 = AegisTransformer(feature_dim=16)
        self.ai2.load_state_dict(torch.load("/app/data/knowledge/ai2.pth"))
        self.ai2.eval()

    def run_full_test(self):
        """
        Проверка узагальнюючої здатності моделей.
        """
        print("--- Запуск валидации Aegis-NDR на эталонном датасете ---")
        df = pd.read_csv(self.data_path)
        X = df.drop('label', axis=1).values
        y_true = df['label'].values
        
        # 1. Тест AI 1 (Идентификация по признакам) [cite: 81, 169]
        y_pred_ai1 = self.ai1.predict(X)
        print("\n[AI 1 Metrics (Supervised)]")
        print(classification_report(y_true, y_pred_ai1))

        # 2. Тест VAE (Выявление аномалий) [cite: 88, 174]
        X_tensor = torch.FloatTensor(X)
        with torch.no_grad():
            reconstructed, _, _ = self.vae(X_tensor)
            # Расчет Reconstruction Error как показателя аномальности [cite: 98, 102]
            mse = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
            y_pred_vae = (mse > 0.05).int().numpy() # Порог из конфига
        
        print("\n[VAE Metrics (Anomaly Detection)]")
        print(confusion_matrix(y_true, y_pred_vae))

        # 3. Тест AI 2 (Анализ поведения / Изоморфные признаки) [cite: 92, 177]
        # Для упрощения подаем как последовательность длиной 1
        X_seq = X_tensor.unsqueeze(1)
        with torch.no_grad():
            scores = self.ai2(X_seq).squeeze().numpy()
            y_pred_ai2 = (scores > 0.8).astype(int)
            
        print("\n[AI 2 Metrics (Behavioral Transformer)]")
        print(classification_report(y_true, y_pred_ai2))

if __name__ == "__main__":
    validator = AegisValidator()
    validator.run_full_test()