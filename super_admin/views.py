from django.middleware.csrf import get_token
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import permissions
from rest_framework import status
from rest_framework.exceptions import ValidationError, NotAuthenticated, APIException, NotFound
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from services.admin_service import AdminService
from services.auth_service import AuthService
from services.dashboard_service import DashboardService
from super_admin.serializers import AdminCreateSerializer, AdminResponseSerializer
from .permissions import IsSuperAdmin, IsAdminUser
from .serializers import AdminUpdateSerializer
from .serializers import LoginSerializer


# class LoginView(APIView):
#   permission_classes = [permissions.AllowAny]
#
#   @swagger_auto_schema(
#     request_body=LoginSerializer,
#     responses={200: "Tokens set in cookies"},
#     operation_summary="Login",
#     operation_description="Authenticates user and sets JWT tokens in HttpOnly cookies."
#   )
#   def post(self, request):
#     serializer = LoginSerializer(data=request.data)
#     serializer.is_valid(raise_exception=True)
#
#     try:
#       user = AuthService.login_user(
#         serializer.validated_data['email'],
#         serializer.validated_data['password']
#       )
#       tokens = AuthService.generate_tokens_for_user(user)
#       response = Response({'message': 'Login successful'})
#       return AuthService.set_tokens_in_cookies(response, tokens)
#
#     except ValidationError as e:
#       return Response({'detail': str(e.detail)}, status=status.HTTP_401_UNAUTHORIZED)
#
#
# class LogoutView(APIView):
#   permission_classes = [permissions.IsAuthenticated]
#
#   @swagger_auto_schema(
#     operation_summary="Logout",
#     request_body=None,
#     responses={205: "Logged out"}
#   )
#   def post(self, request):
#     try:
#       return AuthService.logout_user(request)
#     except NotAuthenticated as e:
#       return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
#     except ValidationError as e:
#       return Response({'detail': str(e.detail)}, status=status.HTTP_400_BAD_REQUEST)
#
#
# class TokenRefreshView(APIView):
#   permission_classes = [permissions.AllowAny]
#
#   @swagger_auto_schema(operation_summary="Refresh Access Token")
#   def post(self, request):
#     refresh_token = request.COOKIES.get('refresh_token')
#     if not refresh_token:
#       return Response({'detail': 'Refresh token missing'}, status=status.HTTP_400_BAD_REQUEST)
#
#     try:
#       refresh = RefreshToken(refresh_token)
#       new_access_token = str(refresh.access_token)
#
#       response = Response({'message': 'Access token refreshed'})
#       response.set_cookie(
#         key='access_token',
#         value=new_access_token,
#         httponly=True,
#         secure=True,
#         samesite='Lax'
#       )
#       return response
#
#     except TokenError:
#       return Response({'detail': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)


# class LoginView(APIView):
#   permission_classes = [permissions.AllowAny]
#
#   @swagger_auto_schema(
#     request_body=LoginSerializer,
#     responses={200: "Tokens set in cookies"},
#   )
#   def post(self, request):
#     serializer = LoginSerializer(data=request.data)
#     serializer.is_valid(raise_exception=True)
#     response = Response()
#
#     try:
#         user = AuthService.login_user(serializer.validated_data['email'], ...)
#         tokens = AuthService.generate_tokens_for_user(user)
#         return AuthService.set_tokens_in_cookies(response, tokens)
#     except ValidationError as e:
#         response.delete_cookie('access_token')
#         response.delete_cookie('refresh_token')
#         return Response({'detail': str(e.detail)}, status=401)
#
#
# class LogoutView(APIView):
#   permission_classes = [permissions.IsAuthenticated]
#
#   @swagger_auto_schema(
#     operation_summary="Logout",
#     request_body=None,
#     responses={205: "Դուրս գալ"}
#   )
#   def post(self, request):
#     try:
#       return AuthService.logout_user(request)
#     except ValidationError as e:
#       # Սխալ refresh token-ի դեպքում
#       return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
#     except Exception as e:
#       # Համաշխարհային սխալների դեպքում
#       return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
#
#
# class TokenRefreshView(APIView):
#   permission_classes = [permissions.AllowAny]
#
#   def post(self, request):
#     refresh_token = request.COOKIES.get('refresh_token')
#     if not refresh_token:
#       return Response(
#         {'detail': 'Refresh token չկա'},
#         status=status.HTTP_400_BAD_REQUEST
#       )
#
#     try:
#       refresh = RefreshToken(refresh_token)
#       new_access_token = str(refresh.access_token)
#       response = Response({'message': 'Access token-ը թարմացվեց'})
#       response.set_cookie(
#         key='access_token',
#         value=new_access_token,
#         httponly=True,
#         secure=True,
#         samesite='Lax'
#       )
#       return response
#
#     except TokenError:
#       # Եթե refresh_token-ն անվավեր է՝ մաքրել cookies-ը
#       response = Response(
#         {'detail': 'Ինվալիդ refresh token'},
#         status=status.HTTP_401_UNAUTHORIZED
#       )
#       response.delete_cookie('access_token')
#       response.delete_cookie('refresh_token')
#       return response


class LoginView(APIView):
  permission_classes = [permissions.AllowAny]

  @swagger_auto_schema(request_body=LoginSerializer)
  def post(self, request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    response = Response()

    try:
      user = AuthService.login_user(
        email=serializer.validated_data['email'],
        password=serializer.validated_data['password']
      )
      tokens = AuthService.generate_tokens_for_user(user)
      response.data = {"message": "Login successful"}
      return AuthService.set_tokens_in_cookies(response, tokens)

    except ValidationError as e:
      response.delete_cookie('access_token')
      response.delete_cookie('refresh_token')
      response.data = {"detail": str(e.detail)}
      response.status_code = status.HTTP_401_UNAUTHORIZED
      return response




class LogoutView(APIView):
  permission_classes = [permissions.IsAuthenticated]

  @swagger_auto_schema(
    operation_summary="Logout",
    request_body=None,
    responses={205: "Logged out"}
  )
  def post(self, request):
    try:
      return AuthService.logout_user(request)
    except NotAuthenticated as e:
      return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except ValidationError as e:
      return Response({'detail': str(e.detail)}, status=status.HTTP_400_BAD_REQUEST)

# class LogoutView(APIView):
#   permission_classes = [permissions.IsAuthenticated]
#
#   def post(self, request):
#     return AuthService.logout_user(request)




class TokenRefreshView(APIView):
  permission_classes = [permissions.AllowAny]

  def post(self, request):
    refresh_token = request.COOKIES.get('refresh_token')
    if not refresh_token:
      return Response(
        {"detail": "Refresh token missing"},
        status=status.HTTP_400_BAD_REQUEST
      )

    try:
      refresh = RefreshToken(refresh_token)
      response = Response({"message": "Access token refreshed"})
      response.set_cookie(
        key='access_token',
        value=str(refresh.access_token),
        httponly=True,
        secure=True,
        samesite='Lax',
      )
      return response

    except TokenError:
      response = Response(
        {"detail": "Invalid refresh token"},
        status=status.HTTP_401_UNAUTHORIZED
      )
      response.delete_cookie('access_token')
      response.delete_cookie('refresh_token')
      return response


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


class AdminDashboardView(APIView):
  permission_classes = [IsAdminUser]

  @swagger_auto_schema(
    operation_summary="Admin dashboard",
    operation_description="Accessible only by admin users.",
    responses={
      200: openapi.Response(
        description="Successful request",
        examples={
          "application/json": {"message": "Welcome Admin"}
        }
      ),
      403: "Forbidden. You are not an admin."
    }
  )
  def get(self, request):
    return Response({'message': 'Welcome Admin'})


class CreateAdminView(APIView):
  permission_classes = [IsAuthenticated & IsSuperAdmin]

  @swagger_auto_schema(
    request_body=AdminCreateSerializer,
    responses={201: "Admin user created successfully"},
    operation_summary="Create admin user",
    operation_description="Only SuperAdmin can create new admin users."
  )
  def post(self, request):
    serializer = AdminCreateSerializer(data=request.data)

    if not serializer.is_valid():
      return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
      user = AdminService.create_admin_user(serializer.validated_data)
    except APIException as e:
      return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"detail": "Admin created successfully", "id": user.id, "name": user.name},
                    status=status.HTTP_201_CREATED)


class UpdateAdminView(APIView):
  permission_classes = [IsAuthenticated & IsSuperAdmin]

  @swagger_auto_schema(
    request_body=AdminUpdateSerializer,
    responses={200: openapi.Response("Admin updated", AdminUpdateSerializer),
               400: "Bad Request", 404: "Admin not found"},
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
    responses={204: "Admin deleted successfully", 404: "Admin not found"},
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


class GetCSRFTokenView(APIView):
  permission_classes = [AllowAny]

  def get(self, request):
    csrf_token = get_token(request)
    return Response({'csrfToken': csrf_token})
