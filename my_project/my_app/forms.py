from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from simplemathcaptcha.fields import MathCaptchaField
from django import forms
from django.forms.widgets import PasswordInput, TextInput
from .models import Blog

class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        
    captcha = MathCaptchaField()
    
# - Authenticate a user
class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=TextInput())
    password = forms.CharField(widget=PasswordInput())
    
    
class EmailForm(forms.Form):
    receiver_email = forms.EmailField(label='Receiver Email')

class BlogForm(forms.ModelForm):
    class Meta:
        model = Blog
        fields = ['title', 'description']