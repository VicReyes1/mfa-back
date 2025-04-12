from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register, name='register'),
    path('mfa/qr/', views.get_mfa_qr, name='generate_qr'),
    path('confirmar-mfa/', views.activate_mfa, name='accept_mfa'),
    path('mfa-verify/', views.verify_mfa, name='verify_mfa'),
]
