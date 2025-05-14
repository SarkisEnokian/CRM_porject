from rest_framework import permissions


class IsSuperAdmin(permissions.BasePermission):
  def has_permission(self, request, view):
    return bool(
      request.user and request.user.is_authenticated and request.user.is_superuser
    )


class IsAdminUser(permissions.BasePermission):
  def has_permission(self, request, view):
    return bool(
      request.user and request.user.is_authenticated and request.user.is_staff and not request.user.is_superuser
    )
