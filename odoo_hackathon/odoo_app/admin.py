from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User


class UserAdmin(BaseUserAdmin):
    # Fields to display in the admin list view
    list_display = ("email", "name", "is_active", "is_admin", "created_at")
    list_filter = ("is_active", "is_admin")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Info",
            {"fields": ("name", "terms_and_condition", "subscription_plan")},
        ),
        ("Permissions", {"fields": ("is_active", "is_admin")}),
        ("Important dates", {"fields": ("created_at", "updated_at")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "name",
                    "terms_and_condition",
                    "password1",
                    "password2",
                ),
            },
        ),
    )
    search_fields = ("email", "name")
    ordering = ("email",)
    filter_horizontal = ()


# Register the custom User model with the custom UserAdmin
admin.site.register(User, UserAdmin)
