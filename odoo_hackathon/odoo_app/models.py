from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from .logs import log_info, log_error, log_warning


class UserManager(BaseUserManager):
    def create_user(
        self, email, name, terms_and_condition, password=None, password2=None
    ):
        if not email:
            log_error("Attempted to create a user without an email address.")
            raise ValueError("User must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            terms_and_condition=terms_and_condition,
        )

        if password:
            user.set_password(password)
            log_info(f"Password set for user {email}")
        else:
            log_warning(f"User {email} was created without a password")

        user.save(using=self._db)
        log_info(f"User {email} created successfully.")
        return user

    def create_superuser(self, email, name, terms_and_condition, password=None):
        user = self.create_user(
            email,
            password=password,
            name=name,
            terms_and_condition=terms_and_condition,
        )
        user.is_admin = True
        user.save(using=self._db)
        log_info(f"Superuser {email} created successfully.")
        return user


# Custom User Model
class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)
    terms_and_condition = models.BooleanField()
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    subscription_plan = models.CharField(
        max_length=10, verbose_name="subscription_plan", default="FREE"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "terms_and_condition"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        if self.is_admin:
            log_info(f"User {self.email} has permission: {perm}")
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        log_info(f"User {self.email} has access to module {app_label}")
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        log_info(f"User {self.email} is {'staff' if self.is_admin else 'not staff'}")
        return self.is_admin
