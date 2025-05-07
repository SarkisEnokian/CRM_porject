import re

from rest_framework import serializers

from .models import AdminUser


class LoginSerializer(serializers.Serializer):
  email = serializers.EmailField()
  password = serializers.CharField(write_only=True)


class AdminUserSerializer(serializers.ModelSerializer):
  username = serializers.CharField(required=True)
  name = serializers.CharField(required=True)
  surname = serializers.CharField(required=True)
  email = serializers.EmailField(required=True)
  password = serializers.CharField(write_only=True, required=True)
  confirm_password = serializers.CharField(write_only=True, required=True)

  class Meta:
    model = AdminUser
    fields = ['email', 'username', 'name', 'surname', 'password', 'confirm_password']

  def validate_username(self, value):
    value = value.strip()
    if len(value) < 5:
      raise serializers.ValidationError("Username must be at least 2 characters long.")
    return value

  def validate_name(self, value):
    value = value.strip()
    if not re.match(r'^[a-zA-Z]{2,50}$', value):
      raise serializers.ValidationError("Name must contain only letters and be 2–50 characters long.")
    return value

  def validate_surname(self, value):
    value = value.strip()
    if not re.match(r'^[a-zA-Z]{2,50}$', value):
      raise serializers.ValidationError("Surname must contain only letters and be 2–50 characters long.")
    return value

  def validate_email(self, value):
    if AdminUser.objects.filter(email=value).exists():
      raise serializers.ValidationError("Email is already in use.")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
      raise serializers.ValidationError("Invalid email format.")
    return value

  def validate_password(self, value):
    value = value.strip()
    if len(value) < 8:
      raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', value):
      raise serializers.ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', value):
      raise serializers.ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', value):
      raise serializers.ValidationError("Password must contain at least one digit.")
    if not re.search(r'[^\w\s]', value):
      raise serializers.ValidationError("Password must contain at least one special character.")
    if " " in value:
      raise serializers.ValidationError("Password can't contain spaces.")
    return value

  def validate(self, data):
    if data['password'] != data['confirm_password']:
      raise serializers.ValidationError("Passwords do not match.")
    return data

  def create(self, validated_data):
    validated_data.pop('confirm_password')
    password = validated_data.pop('password')
    user = AdminUser(**validated_data)
    user.set_password(password)
    user.is_staff = True
    user.save()
    return user
