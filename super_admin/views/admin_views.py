from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.exceptions import APIException, NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from services.admin_service import AdminService
from super_admin.serializers.admin_serializers import (AdminCreateSerializer, AdminResponseSerializer,
                                                       AdminRoleUpdateSerializer, AdminUpdateSerializer)
from utils.permissions import IsSuperAdmin


class CreateAdminView(APIView):
  permission_classes = [IsAuthenticated & IsSuperAdmin]

  @swagger_auto_schema(
    request_body=AdminCreateSerializer,
    responses={
      201: openapi.Response("Admin user created successfully"),
      400: openapi.Response("Bad Request"),
      500: openapi.Response("Internal Server Error")
    },
    operation_summary="Create admin user",
    operation_description="Only SuperAdmin can create new admin users.",
  )
  def post(self, request):
    serializer = AdminCreateSerializer(data=request.data)

    if not serializer.is_valid():
      return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
      user = AdminService.create_admin_user(serializer.validated_data)
    except APIException as e:
      return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
      return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"detail": "Admin created successfully", "id": user.id, "name": user.name},
                    status=status.HTTP_201_CREATED)


class UpdateAdminView(APIView):
  permission_classes = [IsAuthenticated & IsSuperAdmin]

  @swagger_auto_schema(
    request_body=AdminUpdateSerializer,
    responses={
      200: openapi.Response("Admin updated"),
      400: openapi.Response("Bad Request"),
      404: openapi.Response("Admin not found"),
      500: openapi.Response("Internal Server Error")
    },
    operation_summary="Update admin user",
    operation_description="Only SuperAdmin can update admin user details.",
    tags=["Admin Management"]
  )
  def put(self, request, pk):
    serializer = AdminUpdateSerializer(data=request.data)

    if not serializer.is_valid():
      return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
      updated_user = AdminService.update_admin_user(pk, serializer.validated_data)
    except NotFound as e:
      return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
    except APIException as e:
      return Response({"detail": str(e)}, status=e.status_code)
    except Exception as e:
      return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    updated_serializer = AdminResponseSerializer(updated_user)

    return Response({
      "detail": "Admin updated",
      "updated_data": updated_serializer.data
    }, status=status.HTTP_200_OK)


class DeleteAdminView(APIView):
  permission_classes = [IsAuthenticated & IsSuperAdmin]

  @swagger_auto_schema(
    responses={
      204: openapi.Response("Admin deleted successfully"),
      404: openapi.Response("Admin not found"),
      500: openapi.Response("Internal Server Error")
    },
    operation_summary="Delete admin user",
    operation_description="Only SuperAdmin can delete admin users.",
    tags=["Admin Management"]
  )
  def delete(self, request, pk):
    try:
      AdminService.delete_admin_user(pk)
    except NotFound as e:
      return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
    except Exception:
      return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"detail": "Admin deleted successfully."}, status=status.HTTP_200_OK)


class UpdateRolesView(APIView):
  permission_classes = [IsAuthenticated & IsSuperAdmin]

  @swagger_auto_schema(
    request_body=AdminRoleUpdateSerializer,
    responses={
      200: openapi.Response("Admin role updated successfully"),
      400: openapi.Response("Bad Request"),
      404: openapi.Response("Admin not found"),
      500: openapi.Response("Internal Server Error")
    },
    operation_summary="Update roles of admin user",
    operation_description="Only SuperAdmin can update the roles of admin users.",
    tags=["Admin Management"]
  )
  def patch(self, request, pk):
    role_serializer = AdminRoleUpdateSerializer(data=request.data, partial=True)

    if not role_serializer.is_valid():
      return Response(role_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
      updated_user = AdminService.role_update_admin_user(pk, role_serializer.validated_data)
    except NotFound as e:
      return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
    except APIException as e:
      return Response({"detail": str(e)}, status=e.status_code)
    except Exception as e:
      return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    updated_serializer = AdminResponseSerializer(updated_user)

    return Response({
      "detail": "Admin role updated",
      "updated_data": updated_serializer.data
    }, status=status.HTTP_200_OK)
