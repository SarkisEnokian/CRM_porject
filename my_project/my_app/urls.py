from django.urls import path
from . import views

urlpatterns = [
    path('', views.homepage, name=''),
    path('register', views.register, name='register'),
    path('my-login', views.my_login, name='my-login'),
    path('dashboard', views.dashboard, name='dashboard'),
    path('user-logout', views.user_logout, name='user-logout'),
    path('send_email', views.send_email, name='send_email'),
    path('email_sent', views.email_sent, name='email_sent'),
    path('reset_password', views.reset_password, name='reset_password'),
    path('blogs', views.blogs, name='blogs'),
    path('make_blog', views.make_blog, name='make_blog'),
    path('my_blogs', views.my_blogs, name='my_blogs')
]