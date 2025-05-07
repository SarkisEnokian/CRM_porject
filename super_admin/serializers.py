import re

from rest_framework import serializers

from error_messages import ERROR_MESSAGES
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
      raise serializers.ValidationError(ERROR_MESSAGES['username_length'])
    return value

  def validate_name(self, value):
    value = value.strip()
    if not re.match(r'^[a-zA-Z]{2,50}$', value):
      raise serializers.ValidationError(ERROR_MESSAGES['name_format'])
    return value

  def validate_surname(self, value):
    value = value.strip()
    if not re.match(r'^[a-zA-Z]{2,50}$', value):
      raise serializers.ValidationError(ERROR_MESSAGES['surname_format'])
    return value

  def validate_email(self, value):
    if AdminUser.objects.filter(email=value).exists():
      raise serializers.ValidationError(ERROR_MESSAGES['email_taken'])
    if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
      raise serializers.ValidationError(ERROR_MESSAGES['email_invalid'])
    return value

  def validate_password(self, value):
    value = value.strip()
    if len(value) < 8:
      raise serializers.ValidationError(ERROR_MESSAGES['password_length'])
    if not re.search(r'[A-Z]', value):
      raise serializers.ValidationError(ERROR_MESSAGES['password_upper'])
    if not re.search(r'[a-z]', value):
      raise serializers.ValidationError(ERROR_MESSAGES['password_lower'])
    if not re.search(r'\d', value):
      raise serializers.ValidationError(ERROR_MESSAGES['password_digit'])
    if not re.search(r'[^\w\s]', value):
      raise serializers.ValidationError(ERROR_MESSAGES['password_special'])
    if " " in value:
      raise serializers.ValidationError(ERROR_MESSAGES['password_spaces'])
    return value

  def validate(self, data):
    if data['password'] != data['confirm_password']:
      raise serializers.ValidationError(ERROR_MESSAGES['password_match'])
    return data

  def create(self, validated_data):
    validated_data.pop('confirm_password')
    password = validated_data.pop('password')
    user = AdminUser(**validated_data)
    user.set_password(password)
    user.is_staff = True
    user.save()
    return user

