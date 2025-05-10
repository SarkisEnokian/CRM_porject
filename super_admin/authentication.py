from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import ExpiredTokenError, TokenError
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
            user_id = token['user_id']

        except ExpiredTokenError:
            if not refresh_token:
                raise AuthenticationFailed("Access token expired and no refresh token available")

            try:
                refresh = RefreshToken(refresh_token)
                new_access_token = refresh.access_token

                user_id = refresh['user_id']
                user = User.objects.get(id=user_id)

                # Attach new token to request so middleware can set it
                request._new_access_token = str(new_access_token)

                return (user, None)

            except TokenError:
                raise AuthenticationFailed("Invalid refresh token")
            except User.DoesNotExist:
                raise AuthenticationFailed("User not found")

        except TokenError:
            raise AuthenticationFailed("Invalid token")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        return (user, None)
