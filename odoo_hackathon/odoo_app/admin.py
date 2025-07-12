from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Item, ItemImage, Swap


# Custom UserAdmin for User model
class UserAdmin(BaseUserAdmin):
    list_display = ("email", "name", "is_active", "is_staff", "is_superuser")
    list_filter = ("is_active", "is_staff", "is_superuser")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("name", "points_balance")}),
        (
            "Permissions",
            {"fields": ("is_active", "is_staff", "is_superuser", "is_admin")},
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "name",
                    "password1",
                    "password2",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_admin",
                ),
            },
        ),
    )
    search_fields = ("email", "name")
    ordering = ("email",)
    filter_horizontal = ()

    def get_fieldsets(self, request, obj=None):
        # Dynamic fieldsets for adding vs. editing
        if obj:  # Editing existing user
            return self.fieldsets
        return self.add_fieldsets


# Inline admin for ItemImage to display images within Item admin
class ItemImageInline(admin.TabularInline):
    model = ItemImage
    extra = 1  # Number of empty forms to display
    fields = ("image", "uploaded_at")
    readonly_fields = ("uploaded_at",)


# Admin for Item model
class ItemAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "title",
        "owner",
        "status",
        "points_value",
        "category",
        "type",
        "condition",
        "created_at",
    )
    list_filter = ("status", "category", "type", "condition", "created_at")
    search_fields = ("title", "description", "owner__email", "tags")
    list_editable = ("status", "points_value", "category", "type", "condition")
    readonly_fields = ("created_at", "updated_at")
    inlines = [ItemImageInline]  # Added to manage ItemImage
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "id",
                    "title",
                    "description",
                    "owner",
                    "status",
                    "points_value",
                    "image",
                    "category",
                    "type",
                    "size",
                    "condition",
                    "tags",
                )
            },
        ),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    def get_queryset(self, request):
        # Optimize queryset by selecting related owner
        return super().get_queryset(request).select_related("owner")


# Admin for ItemImage model
class ItemImageAdmin(admin.ModelAdmin):
    list_display = ("id", "item", "image", "uploaded_at")
    list_filter = ("uploaded_at",)
    search_fields = ("item__title", "image")
    readonly_fields = ("uploaded_at",)

    def get_queryset(self, request):
        # Optimize queryset by selecting related item
        return super().get_queryset(request).select_related("item")


# Admin for Swap model
class SwapAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "requester",
        "item_offered",
        "item_requested",
        "status",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = ("requester__email", "item_offered__title", "item_requested__title")
    list_editable = ("status",)
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "requester",
                    "item_offered",
                    "item_requested",
                    "status",
                )
            },
        ),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    def get_queryset(self, request):
        # Optimize queryset by selecting related fields
        return (
            super()
            .get_queryset(request)
            .select_related("requester", "item_offered", "item_requested")
        )

    def get_actions(self, request):
        # Custom action to mark swaps as completed
        actions = super().get_actions(request)
        actions["mark_as_completed"] = (
            self.mark_as_completed,
            "mark_as_completed",
            "Mark selected swaps as completed",
        )
        return actions

    def mark_as_completed(self, request, queryset):
        # Custom action to mark swaps as completed and update item statuses
        for swap in queryset:
            if swap.status != "completed":
                swap.status = "completed"
                swap.item_offered.status = "swapped"
                swap.item_requested.status = "swapped"
                swap.item_offered.save()
                swap.item_requested.save()
                swap.save()
        self.message_user(request, "Selected swaps marked as completed.")


# Register models with their respective admin classes
admin.site.register(User, UserAdmin)
admin.site.register(Item, ItemAdmin)
admin.site.register(ItemImage, ItemImageAdmin)
admin.site.register(Swap, SwapAdmin)
