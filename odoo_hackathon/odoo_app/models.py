from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.utils import timezone


class UserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_staff", True)  # Add this
        return self.create_user(email, name, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    points_balance = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    terms_and_condition = models.BooleanField(default=False)  # Add this field

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    def __str__(self):
        return self.email


# Item Model for Swapping
# models.py
class Item(models.Model):
    STATUS_CHOICES = (
        ("available", "Available"),
        ("pending", "Pending"),
        ("swapped", "Swapped"),
    )
    CONDITION_CHOICES = (
        ("new", "New"),
        ("like_new", "Like New"),
        ("good", "Good"),
        ("fair", "Fair"),
        ("poor", "Poor"),
    )
    CATEGORY_CHOICES = (
        ("clothing", "Clothing"),
        ("electronics", "Electronics"),
        ("furniture", "Furniture"),
        ("books", "Books"),
        ("other", "Other"),
    )
    TYPE_CHOICES = (
        ("men", "Men"),
        ("women", "Women"),
        ("unisex", "Unisex"),
        ("other", "Other"),
    )
    SIZE_CHOICES = (
        ("xs", "XS"),
        ("s", "S"),
        ("m", "M"),
        ("l", "L"),
        ("xl", "XL"),
        ("other", "Other"),
    )

    title = models.CharField(max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="items")
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="available"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.URLField(blank=True, null=True)
    points_value = models.IntegerField(default=0)
    category = models.CharField(
        max_length=50, choices=CATEGORY_CHOICES, default="other"
    )
    type = models.CharField(max_length=50, choices=TYPE_CHOICES, default="other")
    size = models.CharField(max_length=50, choices=SIZE_CHOICES, default="other")
    condition = models.CharField(
        max_length=50, choices=CONDITION_CHOICES, default="good"
    )
    tags = models.CharField(
        max_length=255, blank=True, null=True
    )  # Comma-separated tags

    def __str__(self):
        return self.title


# models.py
class ItemImage(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="images")
    image = models.URLField()
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for {self.item.title}"


# Swap Model for Tracking Swap Transactions
class Swap(models.Model):
    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("accepted", "Accepted"),
        ("completed", "Completed"),
        ("cancelled", "Cancelled"),
    )

    requester = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="requested_swaps"
    )
    item_offered = models.ForeignKey(
        Item, on_delete=models.CASCADE, related_name="offered_swaps"
    )
    item_requested = models.ForeignKey(
        Item, on_delete=models.CASCADE, related_name="requested_swaps"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Swap: {self.item_offered} for {self.item_requested} ({self.status})"
