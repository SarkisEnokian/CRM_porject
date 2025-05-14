from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin

class RefreshTokenMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if hasattr(request, '_new_access_token'):
            response.set_cookie(
                key='access_token',
                value=request._new_access_token,
                httponly=True,
                secure=True,
                samesite='Lax',
                max_age=60
            )

        if getattr(request, '_clear_tokens', False):
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')

        return response