from rest_framework.exceptions import NotFound, ValidationError, APIException
from super_admin.models import AdminUser

class AdminService:

    @staticmethod
    def create_admin_user(validated_data):
        if validated_data.get('password') != validated_data.pop('confirm_password', None):
            raise ValidationError("Passwords do not match")

        try:
            user = AdminUser.objects.create_user(**validated_data)
        except Exception as e:
            raise APIException(f"Error creating admin user: {str(e)}")

        return user

    @staticmethod
    def update_admin_user(user_id, validated_data):
        try:
            user = AdminUser.objects.get(id=user_id)
        except AdminUser.DoesNotExist:
            raise NotFound(f"Admin with id {user_id} not found")
        except Exception as e:
            raise APIException(f"Error updating admin user: {str(e)}")

        for key, value in validated_data.items():
            setattr(user, key, value)
        user.save()
        return user

    @staticmethod
    def delete_admin_user(user_id):
        try:
            user = AdminUser.objects.get(id=user_id)
        except AdminUser.DoesNotExist:
            raise NotFound(f"Admin with id {user_id} not found")
        except Exception as e:
            raise APIException(f"Error deleting admin user: {str(e)}")

        user.delete()
        return True
