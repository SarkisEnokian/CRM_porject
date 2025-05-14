from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError, ExpiredTokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

User = get_user_model()


class CookieJWTAuthentication(BaseAuthentication):
  def authenticate(self, request):
    access_token = request.COOKIES.get('access_token')
    refresh_token = request.COOKIES.get('refresh_token')

    if not access_token:
      return None

    try:
      token = AccessToken(access_token)
      user = User.objects.get(id=token['user_id'])
      return (user, None)

    except ExpiredTokenError:
      if not refresh_token:
        raise AuthenticationFailed("Access token expired, no refresh token")

      try:
        refresh = RefreshToken(refresh_token)
        user = User.objects.get(id=refresh['user_id'])
        request._new_access_token = str(refresh.access_token)
        return (user, None)

      except (TokenError, User.DoesNotExist):
        request._clear_tokens = True
        raise AuthenticationFailed("Invalid refresh token")

    except (TokenError, User.DoesNotExist):
      request._clear_tokens = True
      raise AuthenticationFailed("Invalid token")
