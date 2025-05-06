# from django.contrib import admin
# # from django.urls import path, include
# #
# # urlpatterns = [
# #     path('admin/', admin.site.urls),
# #     path('superadmin/', include('super_admin.urls'))
# # ]
#
# from django.urls import path, include
#
# urlpatterns = [
#   path('admin/', admin.site.urls),
#   path('api/superadmin/', include('superadmin.urls')),
# ]



from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
  path('admin/', admin.site.urls),
  path('api/', include('super_admin.urls')),

  path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),       # access + refresh
  path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),       # refresh only
]
