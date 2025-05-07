from django.contrib.auth import authenticate
from django.middleware.csrf import get_token
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import permissions
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .permissions import IsSuperAdmin, IsAdminUser
from .serializers import LoginSerializer, AdminUserSerializer


class LoginView(APIView):
  permission_classes = [permissions.AllowAny]

  @swagger_auto_schema(
    request_body=LoginSerializer,
    responses={200: "Tokens set in cookies"},
    operation_summary="Login",
    operation_description="Authenticates user and sets JWT tokens in HttpOnly cookies."
  )
  def post(self, request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    user = authenticate(request, email=email, password=password)

    if not user:
      return Response({'detail': 'Invalid credentials'}, status=401)

    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)

    response = Response({'message': 'Login successful'})
    response.set_cookie(
      key='access_token',
      value=access,
      httponly=True,
      secure=True,
      samesite='Lax'
    )
    response.set_cookie(
      key='refresh_token',
      value=str(refresh),
      httponly=True,
      secure=True,
      samesite='Lax'
    )
    return response


class LogoutView(APIView):
  permission_classes = [IsAuthenticated]

  @swagger_auto_schema(
    operation_summary="Logout",
    request_body=None,
    responses={205: "Logged out"}
  )
  def post(self, request):
    refresh_token = request.COOKIES.get("refresh_token")
    if not refresh_token:
      return Response({"detail": "Refresh token missing"}, status=400)

    try:
      token = RefreshToken(refresh_token)
      token.blacklist()
    except Exception:
      return Response({"detail": "Invalid token"}, status=400)

    response = Response({"detail": "Logged out successfully"}, status=205)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response

  class TokenRefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
      refresh_token = request.COOKIES.get('refresh_token')
      if not refresh_token:
        return Response({'detail': 'Refresh token missing'}, status=400)

      try:
        refresh = RefreshToken(refresh_token)
        access_token = str(refresh.access_token)

        response = Response({'message': 'Token refreshed'})
        response.set_cookie(
          key='access_token',
          value=access_token,
          httponly=True,
          secure=True,
          samesite='Lax'
        )
        return response

      except TokenError:
        return Response({'detail': 'Invalid refresh token'}, status=401)


class SuperAdminDashboardView(APIView):
  permission_classes = [IsSuperAdmin]

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
    return Response({'message': 'Welcome SuperAdmin'})


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


class CreateAdminUserView(APIView):
  permission_classes = [IsSuperAdmin]

  @swagger_auto_schema(
    request_body=AdminUserSerializer,
    responses={201: "Admin user created successfully"},
    operation_summary="Create admin user",
    operation_description="Only SuperAdmin can create new admin users."
  )
  def post(self, request):
    serializer = AdminUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({'message': 'Admin user created successfully'}, status=status.HTTP_201_CREATED)


class GetCSRFTokenView(APIView):
  permission_classes = [AllowAny]

  def get(self, request):
    csrf_token = get_token(request)
    return Response({'csrfToken': csrf_token})


class TokenRefreshView(APIView):
  permission_classes = [permissions.AllowAny]

  def post(self, request):
    refresh_token = request.COOKIES.get('refresh_token')
    if not refresh_token:
      return Response({'detail': 'No refresh token found'}, status=400)

    try:
      refresh = RefreshToken(refresh_token)
      new_access_token = str(refresh.access_token)

      response = Response({'message': 'Token refreshed'})
      response.set_cookie(
        key='access_token',
        value=new_access_token,
        httponly=True,
        secure=True,
        samesite='Lax'
      )
      return response
    except TokenError:
      return Response({'detail': 'Invalid refresh token'}, status=401)
