from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

class AdminManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        if not username:
            raise ValueError('Username is required')

        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)  # Hash the password securely
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        # Check if there is already a superuser, if so, set is_superuser=False for the new one
        if AdminUser.objects.filter(is_superuser=True).exists():
            extra_fields.setdefault('is_superuser', False)
        else:
            extra_fields.setdefault('is_superuser', True)

        extra_fields.setdefault('is_staff', True)  # Superuser must be staff
        return self.create_user(email, username, password, **extra_fields)


class AdminUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255, blank=True)
    surname = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = AdminManager()

    USERNAME_FIELD = 'email'  # used to login
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email
