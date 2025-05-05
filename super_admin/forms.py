from super_admin.models import AdminUser
from django import forms


class SuperAdminLoginForm(forms.Form):
    email = forms.EmailField(label='Email')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')
    
    
class AdminUserCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, label='Password')

    class Meta:
        model = AdminUser
        fields = ['email', 'username', 'password']