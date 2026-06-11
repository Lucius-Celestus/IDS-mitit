import torch
import torch.nn as nn

class AegisTransformer(nn.Module):
    def __init__(self, feature_dim=16, d_model=64, nhead=4):
        super(AegisTransformer, self).__init__()
        # Проекция вектора признаков в пространство модели
        self.embedding = nn.Linear(feature_dim, d_model)
        
        # Кодировщик Transformer для анализа временных зависимостей
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=2)
        
        # Выходной слой для финальной классификации
        self.classifier = nn.Linear(d_model, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # x shape: (batch, seq_len, feature_dim)
        x = self.embedding(x)
        x = self.transformer(x)
        # Берем среднее по последовательности для классификации
        x = x.mean(dim=1)
        return self.sigmoid(self.classifier(x))