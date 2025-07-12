from django.urls import path
from . import views
from odoo_app.views import (
    SendPasswordResetEmailView,
    UserChangePasswordView,
    UserLoginView,
    UserRegistrationView,
    UserPasswordResetView,
    LogoutView,
)


urlpatterns = [
    # AuthenticationAPIEndpoints
    path("auth/register", UserRegistrationView.as_view(), name="register"),
    path("auth/login", UserLoginView.as_view(), name="login"),
    path("auth/logout", LogoutView.as_view(), name="logout"),
]
