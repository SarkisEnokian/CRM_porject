from drf_yasg.utils import swagger_auto_schema
from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError, NotAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from services.auth_service import AuthService
from super_admin.serializers.auth_serializers import LoginSerializer


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
