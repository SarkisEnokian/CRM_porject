from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from services.dashboard_service import DashboardService
from super_admin.serializers.admin_serializers import AdminResponseSerializer
from utils.permissions import IsSuperAdmin, IsAdminUser


class AdminListView(APIView):
  permission_classes = [IsAuthenticated & IsSuperAdmin]

  @swagger_auto_schema(
    operation_summary="SuperAdmin dashboard",
    operation_description="Accessible only by superadmin users.",
    responses={
      200: openapi.Response(
        description="Successful request",
        examples={
          "application/json": {"message": "Welcome SuperAdmin"}
        }
      ),
      403: "Forbidden. You are not a superadmin."
    }
  )
  def get(self, request):
    try:
      admins = DashboardService.get_admins()
      serializer = AdminResponseSerializer(admins, many=True)
      return Response(serializer.data, status=status.HTTP_200_OK)
    except NotFound as e:
      return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
      return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class SuperAdminDashboardView(APIView):
#   permission_classes = [IsSuperAdmin]
#
#   @swagger_auto_schema(
#     operation_summary="SuperAdmin dashboard",
#     operation_description="Accessible only by superadmin users.",
#     responses={
#       200: openapi.Response(
#         description="Successful request",
#         examples={
#           "application/json": {"message": "Welcome SuperAdmin"}
#         }
#       ),
#       403: "Forbidden. You are not a superadmin."
#     }
#   )
#   def get(self, request):
#     return Response({'message': 'Welcome SuperAdmin'})


# class AdminDashboardView(APIView):
#   permission_classes = [IsAdminUser]
#
#   @swagger_auto_schema(
#     operation_summary="Admin dashboard",
#     operation_description="Accessible only by admin users.",
#     responses={
#       200: openapi.Response(
#         description="Successful request",
#         examples={
#           "application/json": {"message": "Welcome Admin"}
#         }
#       ),
#       403: "Forbidden. You are not an admin."
#     }
#   )
#   def get(self, request):
#     return Response({'message': 'Welcome Admin'})
