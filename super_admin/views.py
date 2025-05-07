# # from django.shortcuts import render, redirect
# # from django.contrib.auth import authenticate, login
# # from .forms import SuperAdminLoginForm
# # from django.views.decorators.csrf import csrf_protect
# # from django.contrib.auth import login
# # from .forms import SuperAdminLoginForm, AdminUserCreationForm
# # from .models import AdminUser
# #
# #
# # @csrf_protect
# # def superadmin_login_view(request):
# #   if request.method == 'POST':
# #     form = SuperAdminLoginForm(request.POST)
# #     if form.is_valid():
# #       email = form.cleaned_data['email']
# #       password = form.cleaned_data['password']
# #       user = authenticate(request, email=email, password=password)
# #
# #       if user is not None:
# #         login(request, user)
# #         # Redirect based on role
# #         if user.is_superuser:
# #           return redirect('super_admin_dashboard')
# #         elif user.is_staff:
# #           return redirect('admin_dashboard')
# #         else:
# #           form.add_error(None, 'Access denied.')
# #       else:
# #         form.add_error(None, 'Invalid email or password')
# #   else:
# #     form = SuperAdminLoginForm()
# #
# #   return render(request, 'super_admin/login.html', {'form': form})
# #
# #
# # def super_admin_dashboard(request):
# #   if request.method == 'POST':
# #     form = AdminUserCreationForm(request.POST)
# #     if form.is_valid():
# #       email = form.cleaned_data['email']
# #       username = form.cleaned_data['username']
# #       password = form.cleaned_data['password']
# #       # Create new admin user
# #       AdminUser.objects.create_superuser(email=email, username=username, password=password)
# #       return redirect('super_admin_dashboard')  # Redirect to avoid re-submission on refresh
# #   else:
# #     form = AdminUserCreationForm()
# #
# #   return render(request, 'super_admin/super_admin_dashboard.html', {'form': form})
# #
# #
# # def admin_dashboard(request):
# #   return render(request, 'super_admin/admin_dashboard.html')
#
#
# # from django.contrib.auth import authenticate
# # from rest_framework import status, permissions
# # from rest_framework.response import Response
# # from rest_framework.views import APIView
# # from rest_framework_simplejwt.tokens import RefreshToken
# #
# # from super_admin.serializers import SuperAdminLoginSerializer, AdminUserCreateSerializer
# #
# #
# # class SuperAdminLoginView(APIView):
# #   permission_classes = [permissions.AllowAny]
# #
# #   def post(self, request):
# #     serializer = SuperAdminLoginSerializer(data=request.data)
# #     serializer.is_valid(raise_exception=True)
# #
# #     email = serializer.validated_data['email']
# #     password = serializer.validated_data['password']
# #     user = authenticate(request, email=email, password=password)
# #
# #     if user is not None and user.is_superuser:
# #       refresh = RefreshToken.for_user(user)
# #       return Response({
# #         'access': str(refresh.access_token),
# #         'refresh': str(refresh),
# #       })
# #     return Response({'detail': 'Invalid credentials or not superuser'}, status=status.HTTP_401_UNAUTHORIZED)
# #
# #
# # class AdminDashboardView(APIView):
# #   permission_classes = [permissions.IsAuthenticated]
# #
# #   def get(self, request):
# #     if not request.user.is_staff:
# #       return Response({'detail': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
# #     return Response({'message': 'Welcome to admin dashboard'})
#
#
# from django.contrib.auth import authenticate
# from rest_framework import status, permissions
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
#
# from .permissions import IsSuperAdmin, IsAdminUser
# # from .serializers import SuperAdminLoginSerializer, AdminUserCreateSerializer
#
#
# # class SuperAdminLoginView(APIView):
# #   permission_classes = [permissions.AllowAny]
# #
# #   def post(self, request):
# #     serializer = SuperAdminLoginSerializer(data=request.data)
# #     serializer.is_valid(raise_exception=True)
# #
# #     email = serializer.validated_data['email']
# #     password = serializer.validated_data['password']
# #     user = authenticate(request, email=email, password=password)
# #
# #     if user and user.is_superuser:
# #       refresh = RefreshToken.for_user(user)
# #       return Response({
# #         'access': str(refresh.access_token),
# #         'refresh': str(refresh),
# #       })
# #     return Response(
# #       {'detail': 'Invalid credentials or not a superuser'},
# #       status=status.HTTP_401_UNAUTHORIZED
# #     )
# #
# # class AdminLoginView(APIView):
# #   permission_classes = [permissions.AllowAny]
# #
# #   def post(self, request):
# #     serializer = SuperAdminLoginSerializer(data=request.data)
# #     serializer.is_valid(raise_exception=True)
# #
# #     email = serializer.validated_data['email']
# #     password = serializer.validated_data['password']
# #     user = authenticate(request, email=email, password=password)
# #
# #     if user and user.is_staff and not user.is_superuser:
# #       refresh = RefreshToken.for_user(user)
# #       return Response({
# #         'access': str(refresh.access_token),
# #         'refresh': str(refresh),
# #       })
# #
# #     return Response(
# #       {'detail': 'Invalid credentials or not an admin user'},
# #       status=status.HTTP_401_UNAUTHORIZED
# #     )
#
#
# from django.contrib.auth import authenticate
# from rest_framework import status, permissions
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
# from .serializers import LoginSerializer, AdminUserSerializer
#
#
# class LoginView(APIView):
#     permission_classes = [permissions.AllowAny]
#
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#
#         email = serializer.validated_data['email']
#         password = serializer.validated_data['password']
#         user = authenticate(request, email=email, password=password)
#
#         if user:
#             refresh = RefreshToken.for_user(user)
#
#             # Գեղեցկացնել այս կետը,  ավելի լուրջ մասին հասնելու դեպքում փոխել լոգիկան,
#             # ստուգումներ կատարել, սահմանել ռեյթ լիմիտ, OA2
#
#             if user.is_superuser:
#                 return Response({
#                     'access': str(refresh.access_token),
#                     'refresh': str(refresh),
#                     'dashboard': 'superadmin_dashboard',
#                 })
#             elif user.is_staff:
#                 return Response({
#                     'access': str(refresh.access_token),
#                     'refresh': str(refresh),
#                     'dashboard': 'admin_dashboard',
#                 })
#
#         return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
#
#
#
# class SuperAdminDashboardView(APIView):
#   permission_classes = [IsSuperAdmin]
#
#   def get(self, request):
#     return Response({'message': 'Welcome SuperAdmin'})
#
#
# class AdminDashboardView(APIView):
#   permission_classes = [IsAdminUser]
#
#   def get(self, request):
#     return Response({'message': 'Welcome Admin'})
#
#
# class CreateAdminUserView(APIView):
#   permission_classes = [IsSuperAdmin]
#
#   def post(self, request):
#     serializer = AdminUserSerializer(data=request.data)
#     serializer.is_valid(raise_exception=True)
#     serializer.save()
#     return Response({'message': 'Admin user created successfully'}, status=status.HTTP_201_CREATED)


from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth import authenticate
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, AdminUserSerializer
from .permissions import IsSuperAdmin, IsAdminUser  # assuming you have these


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=LoginSerializer,
        responses={
            200: openapi.Response(
                description="JWT tokens and dashboard info",
                examples={
                    "application/json": {
                        "access": "jwt_access_token",
                        "refresh": "jwt_refresh_token",
                        "dashboard": "admin_dashboard"
                    }
                }
            ),
            401: "Invalid credentials"
        },
        operation_summary="Login user",
        operation_description="Logs in a user with email and password. Returns JWT tokens and dashboard type."
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(request, email=email, password=password)

        if user:
            refresh = RefreshToken.for_user(user)

            if user.is_superuser:
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'dashboard': 'superadmin_dashboard',
                })
            elif user.is_staff:
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'dashboard': 'admin_dashboard',
                })

        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class SuperAdminDashboardView(APIView):
    permission_classes = [IsSuperAdmin]

    @swagger_auto_schema(
        operation_summary="SuperAdmin dashboard",
        operation_description="Accessible only by superadmin users."
    )
    def get(self, request):
        return Response({'message': 'Welcome SuperAdmin'})


class AdminDashboardView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Admin dashboard",
        operation_description="Accessible only by admin users."
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
