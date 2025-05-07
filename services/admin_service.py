from rest_framework.exceptions import NotFound
from super_admin.models import AdminUser
from django.core.exceptions import ObjectDoesNotExist


class AdminService:

    @staticmethod
    def get_all_admins():
        admins = AdminUser.objects.filter(is_staff=True).exclude(is_superuser=True)

        if not admins.exists():
            raise NotFound(detail="Admins not found")
        return admins

    @staticmethod
    def get_admin_info(user):
        try:
            self_admin = AdminUser.objects.get(id=user.id)
        except ObjectDoesNotExist:
            raise NotFound(detail="Admin not found")
        return self_admin

    @staticmethod
    def create_admin_user(data):
        user = AdminUser.objects.create_user(
            email=data['email'],
            username=data['username'],
            password=data['password'],
            name=data.get('name', ''),
            surname=data.get('surname', '')
        )
        return user
