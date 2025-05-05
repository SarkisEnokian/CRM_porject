from django.contrib import admin
from .models import AdminUser

class AdminUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'name', 'surname', 'is_active', 'is_staff')  
    search_fields = ('email', 'username')  
    list_filter = ('is_active', 'is_staff')  
admin.site.register(AdminUser, AdminUserAdmin)