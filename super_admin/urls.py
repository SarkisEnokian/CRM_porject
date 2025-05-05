from django.urls import path
from .views import superadmin_login_view, super_admin_dashboard, admin_dashboard

urlpatterns = [
    path('login/', superadmin_login_view, name='superadmin_login'),
    path('super_admin_dashboard/', super_admin_dashboard, name='super_admin_dashboard'),
    path('admin_dashboard/', admin_dashboard, name='admin_dashboard'),

]