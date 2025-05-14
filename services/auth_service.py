from tokenize import TokenError

from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class AuthService:
  @staticmethod
  def login_user(email: str, password: str):
    user = User.objects.filter(email=email).first()
    if not user or not user.check_password(password):
      raise ValidationError("Invalid credentials")
    return user

  @staticmethod
  def generate_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
      "access": str(refresh.access_token),
      "refresh": str(refresh)
    }

  @staticmethod
  def set_tokens_in_cookies(response, tokens):
    response.set_cookie(
      key='access_token',
      value=tokens['access'],
      httponly=True,
      secure=True,
      samesite='Lax',
    )
    response.set_cookie(
      key='refresh_token',
      value=tokens['refresh'],
      httponly=True,
      secure=True,
      samesite='Lax',
    )
    return response

  @staticmethod
  def blacklist_refresh_token(refresh_token: str):
    try:
      token = RefreshToken(refresh_token)
      token.blacklist()
    except TokenError:
      raise ValidationError("Invalid refresh token")

  @staticmethod
  def logout_user(request):
    refresh_token = request.COOKIES.get("refresh_token")
    if refresh_token:
      AuthService.blacklist_refresh_token(refresh_token)

    response = Response({"detail": "Logged out successfully"}, status=205)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response
