from django.shortcuts import render, redirect
from . forms import CreateUserForm, LoginForm, EmailForm, BlogForm
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.contrib.auth.models import auth
from django.contrib.auth import authenticate, login, logout
import random 
from django.contrib.auth.models import User
from .models import Blog



def homepage(request):
    return render(request, 'my_app/index.html')

def register(request):
    form = CreateUserForm()
    
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('my-login')
    
    context = {'registerform':form}
    
    return render(request, 'my_app/register.html', context=context)

def my_login(request):
    
    form = LoginForm()
    if request.method == 'POST':     
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = request.POST.get('username')
            password = request.POST.get('password')
            
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                auth.login(request, user)
                
                return redirect('dashboard')
    
    context = {'loginform':form}        
    return render(request, 'my_app/my-login.html', context=context)


def user_logout(request):
    
    auth.logout(request)
    
    return redirect('')

@login_required(login_url='my-login')
def dashboard(request):
    return render(request, 'my_app/dashboard.html')


def send_email(request):
    random_generate = random.randint(10000, 99999)
    
    if request.method == 'POST' and 'code' in request.POST:
        entered_code = request.POST['code']
        session_code = request.session.get('reset_code')

        if entered_code == session_code:
            return redirect('reset_password')
        else:
            return render(request, 'my_app/email_sent.html', {
                'error': 'Incorrect code entered. Please try again.'
            })

    elif request.method == 'POST':
        # User has submitted their email to receive a verification code
        form = EmailForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            receiver_email = cd['receiver_email']
            
            # Check if email exists in the system
            if User.objects.filter(email=receiver_email).exists():
                # Store the verification code and email in session
                request.session['reset_code'] = str(random_generate)
                request.session['reset_email'] = receiver_email
                
                # Send the verification code to the user via email
                send_mail(
                    subject='Password Recovery Verification',
                    message=f'Your verification code is: {random_generate}',
                    from_email='gortorozyan1@gmail.com',
                    recipient_list=[receiver_email],
                    fail_silently=False,
                )
                return render(request, 'my_app/email_sent.html', {'email': receiver_email})
            else:
                return render(request, 'my_app/send_email.html', {
                    'form': form,
                    'error': 'This email is not registered in our system.'
                })
    else:
        form = EmailForm()

    return render(request, 'my_app/send_email.html', {'form': form})

def email_sent(request):
    return render(request, 'my_app/email_sent.html')

def reset_password(request):
    if request.method == 'POST':
        new_password = request.POST['new_password']
        email = request.session.get('reset_email')

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            return redirect('my-login') 
        except User.DoesNotExist:
            return redirect('send_email')  

    return render(request, 'my_app/reset_password.html')


def blogs(request):
    blogs = Blog.objects.all() 
    return render(request, 'my_app/blogs.html', {'blogs': blogs})
 

@login_required(login_url='my-login')
def make_blog(request):
    if request.method == 'POST':
        form = BlogForm(request.POST)
        if form.is_valid():
            blog = form.save(commit=False)
            blog.author = request.user      
            blog.save()
            return redirect('blogs')
    else:
        form = BlogForm()
    return render(request, 'my_app/make_blog.html', {'form': form})


@login_required(login_url='my-login')
def my_blogs(request):
    blogs = Blog.objects.filter(author=request.user) 
    return render(request, 'my_app/my_blogs.html', {'blogs': blogs})


