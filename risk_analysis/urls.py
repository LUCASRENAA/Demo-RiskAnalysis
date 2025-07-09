# seu_projeto/urls.py

from django.contrib import admin
from django.urls import path, include # Importe 'include'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')), # Inclui as URLs do seu app 'core'
]