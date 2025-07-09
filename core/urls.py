# core/urls.py

from django.urls import path
from . import views # Importa as views do seu app 'core'

urlpatterns = [
    path('', views.index, name='index'), # Define a rota para a página inicial
    path('api/sca-scan/', views.sca_scan, name='sca_scan'), # Nova rota para a análise SCA
    path('api/dast_scan/', views.dast_scan, name='dast_scan'), # Novo caminho para DAST

]