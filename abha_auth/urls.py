from django.urls import path
from .views import InitiateAuthView, VerifyOTPView

urlpatterns = [
    path('auth/initiate/', InitiateAuthView.as_view(), name='auth_initiate'),
    path('auth/verify/', VerifyOTPView.as_view(), name='auth_verify'),
]
