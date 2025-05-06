# # from django.urls import path
# # from .views import superadmin_login_view, super_admin_dashboard, admin_dashboard
# #
# # urlpatterns = [
# #     path('login/', superadmin_login_view, name='superadmin_login'),
# #     path('super_admin_dashboard/', super_admin_dashboard, name='super_admin_dashboard'),
# #     path('admin_dashboard/', admin_dashboard, name='admin_dashboard'),
# #
# # ]
#
#
# # from django.urls import path
# #
# # from .views import SuperAdminLoginView, AdminDashboardView
# #
# # urlpatterns = [
# #   path('login/', SuperAdminLoginView.as_view(), name='superadmin_login'),
# #   path('admin-dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
# # ]
#
#
# from django.urls import path
# from .views import (
#     SuperAdminLoginView,
#     AdminLoginView,
#     SuperAdminDashboardView,
#     AdminDashboardView,
#     CreateAdminUserView
# )
#
# urlpatterns = [
#     path('login/', SuperAdminLoginView.as_view(), name='superadmin-login'),
#     path('dashboard/', SuperAdminDashboardView.as_view(), name='superadmin-dashboard'),
#     path('admin/dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),
#     path('admin/login/', AdminLoginView.as_view(), name='admin-login'),
#     path('admin/create/', CreateAdminUserView.as_view(), name='create-admin-user'),
# ]
# # from .views import CreateAdminUserView
# #
# # urlpatterns += [
# #     path('dashboard/superadmin/create-admin/', CreateAdminUserView.as_view(), name='create-admin'),
# # ]
# #


# from django.urls import path
# from .views import LoginView, SuperAdminDashboardView, AdminDashboardView
#
# urlpatterns = [
#     path('login/', LoginView.as_view(), name='login'),
#     path('dashboard/superadmin/', SuperAdminDashboardView.as_view(), name='superadmin_dashboard'),
#     path('dashboard/admin/', AdminDashboardView.as_view(), name='admin_dashboard'),
# ]



from django.urls import path
from .views import (
    LoginView,
    SuperAdminDashboardView,
    AdminDashboardView,
    CreateAdminUserView,
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('dashboard/superadmin/', SuperAdminDashboardView.as_view(), name='superadmin_dashboard'),
    path('dashboard/admin/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('create_admin/', CreateAdminUserView.as_view(), name='create_admin_user'),
]
