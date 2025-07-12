from django.urls import path
from . import views
from odoo_app.views import (
    UserLoginView,
    UserRegistrationView,
    LogoutView,
    FeaturedItemsView,
    UserDashboardView,
    ItemCreateView,
    ItemListView,
    ItemDetailView,
    SwapRequestView,
    SwapUpdateView,
    RedeemItemView,
)


urlpatterns = [
    # AuthenticationAPIEndpoints
    path("auth/register", UserRegistrationView.as_view(), name="register"),
    path("auth/login", UserLoginView.as_view(), name="login"),
    path("auth/logout", LogoutView.as_view(), name="logout"),
    path("featured-items/", FeaturedItemsView.as_view(), name="featured-items"),
    path("dashboard/", UserDashboardView.as_view(), name="dashboard"),
    path("items/create/", ItemCreateView.as_view(), name="item-create"),
    path("items/", ItemListView.as_view(), name="item-list"),
    path("items/redeem/", RedeemItemView.as_view(), name="redeem-item"),
    path("items/<int:pk>/", ItemDetailView.as_view(), name="item-detail"),
    path("swaps/create/", SwapRequestView.as_view(), name="swap-request"),
    path("swaps/<int:pk>/update/", SwapUpdateView.as_view(), name="swap-update"),
]
