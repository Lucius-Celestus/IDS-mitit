import torch
import torch.nn as nn
from typing import Tuple

class AegisVAE(nn.Module):
    def __init__(self, input_dim: int = 16, hidden_dim: int = 12, latent_dim: int = 4):
        super(AegisVAE, self).__init__()
        
        # Энкодер: Сжимаем признаки
        # Используем LeakyReLU, чтобы избежать проблемы "умирающих" нейронов
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LeakyReLU(0.2)
        )
        
        # Слой латентного пространства
        self.fc_mu = nn.Linear(hidden_dim // 2, latent_dim)
        self.fc_logvar = nn.Linear(hidden_dim // 2, latent_dim)
        
        # Декодер: Восстанавливаем структуру
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim // 2),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim // 2, hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, input_dim) 
            # Убрали Sigmoid, чтобы работать с ненормированными данными (логитами)
        )

    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        """Трюк с репараметризацией для возможности обратного распространения ошибки."""
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        # Кодируем
        h = self.encoder(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        
        # Выбираем точку в латентном пространстве
        z = self.reparameterize(mu, logvar)
        
        # Декодируем
        return self.decoder(z), mu, logvar

    def get_loss(self, recon_x, x, mu, logvar):
        """
        Расчет функции потерь VAE (BCE/MSE + KL Divergence).
        """
        # Reconstruction Loss (насколько хорошо восстановили)
        recon_loss = nn.functional.mse_loss(recon_x, x, reduction='sum')
        
        # KL Divergence (насколько латентное пространство похоже на нормальное распределение)
        # Формула: -0.5 * sum(1 + log(sigma^2) - mu^2 - sigma^2)
        kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
        
        return recon_loss + kl_loss