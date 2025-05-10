from rest_framework.exceptions import NotFound

from super_admin.models import AdminUser


class DashboardService:
  @staticmethod
  def get_admins():
    admins = AdminUser.objects.filter(is_staff=True).exclude(is_superuser=True)
    if not admins.exists():
      raise NotFound("No admin users found.")
    return admins
