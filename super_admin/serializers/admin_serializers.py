import re

from rest_framework import serializers

from messages.error_messages import ERROR_MESSAGES
from super_admin.models import AdminUser


class AdminCreateSerializer(serializers.ModelSerializer):
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
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if password != confirm_password:
      raise serializers.ValidationError({"confirm_password": "Passwords must match."})
    return data

  def create(self, validated_data):
    validated_data.pop('confirm_password')

    user_fields = ['email', 'username', 'name', 'surname', 'password']
    user_data = {field: validated_data[field] for field in user_fields if field in validated_data}

    admin_user = AdminUser.objects.create_user(**user_data)
    for role_field in [
      'lead_management', 'sales_management', 'marketing_department',
      'finance_department', 'technical_support_CSM', 'backup_security', 'bug_tracking'
    ]:
      setattr(admin_user, role_field, validated_data.get(role_field, False))
    admin_user.save()

    return admin_user


class AdminUpdateSerializer(serializers.ModelSerializer):
  class Meta:
    model = AdminUser
    fields = ['email', 'username', 'name', 'surname']

  def update(self, instance, validated_data):
    for attr, value in validated_data.items():
      setattr(instance, attr, value)
    instance.save()
    return instance


class AdminResponseSerializer(serializers.ModelSerializer):
  class Meta:
    model = AdminUser
    fields = ['id', 'email', 'username', 'name', 'surname']

  def to_representation(self, instance):
    rep = super().to_representation(instance)
    return rep


class AdminRoleUpdateSerializer(serializers.ModelSerializer):
  class Meta:
    model = AdminUser
    fields = ['lead_management', 'sales_management', 'marketing_department', 'finance_department',
              'technical_support_CSM', 'backup_security', 'bug_tracking']

  def update(self, instance, validated_data):
    for attr, value in validated_data.items():
      setattr(instance, attr, value)
    instance.save()
    return instance
