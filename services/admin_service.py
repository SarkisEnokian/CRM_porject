from rest_framework.exceptions import NotFound, APIException

from super_admin.models import AdminUser


class AdminService:

  @staticmethod
  def create_admin_user(validated_data):
    validated_data.pop('confirm_password', None)
    validated_data['is_staff'] = True

    try:
      user = AdminUser.objects.create_user(**validated_data)
    except Exception as e:
      raise APIException(f"Error creating admin user: {str(e)}")

    return user

  @staticmethod
  def update_admin_user(user_id, validated_data):
    user = AdminUser.objects.filter(id=user_id).first()
    if not user:
      raise NotFound(f"Admin with id {user_id} not found")

    for key, value in validated_data.items():
      setattr(user, key, value)

    user.save()
    return user

  @staticmethod
  def delete_admin_user(user_id):
    user = AdminUser.objects.get(id=user_id)
    if not user:
      raise NotFound(f"Admin with id {user_id} not found")

    user.is_active = False
    user.save()
    return True
  
  @staticmethod
  def role_update_admin_user(user_id, validated_data):
    user = AdminUser.objects.filter(id=user_id).first()
    if not user:
      raise NotFound(f"Admin with id {user_id} not found")

    for key, value in validated_data.items():
      setattr(user, key, value)

    user.save()
    return user
