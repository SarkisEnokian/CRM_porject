from django.middleware.csrf import get_token
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class GetCSRFTokenView(APIView):
  permission_classes = [AllowAny]

  def get(self, request):
    csrf_token = get_token(request)
    return Response({'csrfToken': csrf_token})
