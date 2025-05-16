from django.urls import path

from .views.admin_views import CreateAdminView, UpdateAdminView, DeleteAdminView, UpdateRolesView
from .views.auth_views import LoginView, LogoutView, TokenRefreshView
from .views.csrf_views import GetCSRFTokenView 
from .views.dashboard_views import AdminListView
from .views.marketing_department_views import MarketingDepartmentView                             
urlpatterns = [
  path('login/', LoginView.as_view()),
  path('logout/', LogoutView.as_view()),
  path('token/refresh/', TokenRefreshView.as_view()),

  path('csrf/', GetCSRFTokenView.as_view()),

  # path('dashboard/admin/', AdminDashboardView.as_view()),
  path('dashboard/super_admin/', AdminListView.as_view()),

  path('admins/create/', CreateAdminView.as_view()),
  path('admins/update/<int:pk>/', UpdateAdminView.as_view()),
  path('admins/delete/<int:pk>/', DeleteAdminView.as_view()),
  path('admins/roles/<int:pk>/', UpdateRolesView.as_view()),
  path('marketing_department/', MarketingDepartmentView.as_view()),
  # path('marketing_department/', MarketingDepartmentView.as_view()),

  
]
