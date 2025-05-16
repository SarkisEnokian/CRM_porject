from django.middleware.csrf import get_token
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from ..models import MarketingDepartment, AdminUser
from django.shortcuts import get_object_or_404
from rest_framework import status

# class GetMarketingData(APIView):
#     permission_classes = [AllowAny]
#     def get(self, request):
#         all_data = MarketingDepartment.objects.all()
#         return all_data
    
    
    

class MarketingDepartmentView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        day = request.data.get('day')
        mood = request.data.get('mood')
        connect_id = request.data.get('connect_id')

        if not all([day, mood]):
            return Response({'error': 'Day and Mood are required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        connect = None
        if connect_id:
            connect = get_object_or_404(AdminUser, id=connect_id, marketing_department_role=True)

        manager = MarketingDepartment.objects.create(
            day=day,
            mood=mood,
            connect=connect
        )

        return Response({
            'id': manager.id,
            'day': manager.day,
            'mood': manager.mood,
            'connect': manager.connect.id if manager.connect else None
        }, status=status.HTTP_201_CREATED)