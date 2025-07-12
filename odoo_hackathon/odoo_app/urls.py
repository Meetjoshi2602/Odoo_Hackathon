from django.urls import path
from odoo_app.views import (
    UserRegistrationView,
    UserLoginView,
    LogoutView,
    AdminItemListView,
    AdminItemModerationView,
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
    # Authentication Endpoints
    path("auth/register", UserRegistrationView.as_view(), name="register"),
    path("auth/login", UserLoginView.as_view(), name="login"),
    path("auth/logout", LogoutView.as_view(), name="logout"),
    # Item Endpoints
    path("items/", ItemListView.as_view(), name="item-list"),
    path("items/create/", ItemCreateView.as_view(), name="item-create"),
    path("items/<int:pk>/", ItemDetailView.as_view(), name="item-detail"),
    path("items/redeem/", RedeemItemView.as_view(), name="redeem-item"),
    path("featured-items/", FeaturedItemsView.as_view(), name="featured-items"),
    # Swap Endpoints
    path("swaps/create/", SwapRequestView.as_view(), name="swap-request"),
    path("swaps/<int:pk>/update/", SwapUpdateView.as_view(), name="swap-update"),
    # User Dashboard Endpoint
    path("dashboard/", UserDashboardView.as_view(), name="dashboard"),
    # admin Endpoint
    path("admin/items/", AdminItemListView.as_view(), name="admin-item-list"),
    path(
        "admin/items/<int:pk>/moderate/",
        AdminItemModerationView.as_view(),
        name="admin-item-moderate",
    ),
]
