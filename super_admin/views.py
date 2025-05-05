from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import SuperAdminLoginForm
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth import login
from .forms import SuperAdminLoginForm, AdminUserCreationForm
from .models import AdminUser


@csrf_protect
def superadmin_login_view(request):
    if request.method == 'POST':
        form = SuperAdminLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)

            if user is not None:
                login(request, user)
                # Redirect based on role
                if user.is_superuser:
                    return redirect('super_admin_dashboard')
                elif user.is_staff:
                    return redirect('admin_dashboard')
                else:
                    form.add_error(None, 'Access denied.')
            else:
                form.add_error(None, 'Invalid email or password')
    else:
        form = SuperAdminLoginForm()

    return render(request, 'super_admin/login.html', {'form': form})


def super_admin_dashboard(request):
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            # Create new admin user
            AdminUser.objects.create_superuser(email=email, username=username, password=password)
            return redirect('super_admin_dashboard')  # Redirect to avoid re-submission on refresh
    else:
        form = AdminUserCreationForm()

    return render(request, 'super_admin/super_admin_dashboard.html', {'form': form})


def admin_dashboard(request):
    
    return render(request, 'super_admin/admin_dashboard.html')