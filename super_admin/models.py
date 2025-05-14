from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models


class AdminManager(BaseUserManager):
  def create_user(self, email, username, name, surname, password=None, **extra_fields):
    if not email:
      raise ValueError('Email is required')
    if not username:
      raise ValueError('Username is required')
    if not name:
      raise ValueError('Name is required')
    if not surname:
      raise ValueError('Surname is required')

    email = self.normalize_email(email)
    user = self.model(email=email, username=username, name=name, surname=surname, **extra_fields)
    user.set_password(password)
    user.save(using=self._db)

    return user

  def create_superuser(self, email, username, name, surname, password=None, **extra_fields):
    if AdminUser.objects.filter(is_superuser=True).exists():
      extra_fields.setdefault('is_superuser', False)
    else:
      extra_fields.setdefault('is_superuser', True)

    extra_fields.setdefault('is_staff', True)
    extra_fields.update({
      'lead_management': True,
      'sales_management': True,
      'marketing_department': True,
      'finance_department': True,
      'technical_support_CSM': True,
      'backup_security': True,
      'bug_tracking': True,
    })
    return self.create_user(email, username, name, surname, password, **extra_fields)


class AdminUser(AbstractBaseUser, PermissionsMixin):
  email = models.EmailField(max_length=255, unique=True)
  username = models.CharField(max_length=255, unique=True)
  name = models.CharField(max_length=255, blank=True)
  surname = models.CharField(max_length=255, blank=True)
  is_active = models.BooleanField(default=True)
  is_staff = models.BooleanField(default=False)
  lead_management = models.BooleanField(default=False)
  sales_management = models.BooleanField(default=False)
  marketing_department = models.BooleanField(default=False)
  finance_department = models.BooleanField(default=False)
  technical_support_CSM = models.BooleanField(default=False)
  backup_security = models.BooleanField(default=False)
  bug_tracking = models.BooleanField(default=False)

  objects = AdminManager()

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['username', 'name', 'surname']

  def __str__(self):
    return self.email
