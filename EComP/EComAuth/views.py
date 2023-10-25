from django.shortcuts import render,HttpResponse,redirect
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
# to activate user account
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import NoReverseMatch,reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes,force_str

from django.utils.encoding import DjangoUnicodeDecodeError
# Getting tokens
from .utils import TokenGenerator,generate_token
# Email
from django.core.mail import send_mail,EmailMultiAlternatives
from django.core.mail import BadHeaderError,send_mail
from django.core import mail
from django.conf import settings
from django.core.mail import EmailMessage

# reset password token generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# threading
import threading

class EmailThread(threading.Thread):
    def __init__(self,email_msg):
        self.email_msg = email_msg
        threading.Thread.__init__(self)
    def run(self):
        self.email_msg.send()

from django.contrib.auth import get_user_model

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(request, "Thank you for your email confirmation. Now you can login your account.")
        return redirect('/EComAuth/login')
    else:
        messages.error(request, "Activation link is invalid!")
        return render(request,'auth/activatefail.html')

def activateEmail(request, user, to_email):
    mail_subject = "Activate your user account."
    message = render_to_string("auth/activate.html", {
        'user': user.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': generate_token.make_token(user),
        "protocol": 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    EmailThread(email).start()
# Create your views here.



def signup(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['pass1']
        conf_password = request.POST['pass2']
        if password != conf_password:
            messages.warning(request,"Password is not Matching")
            return render(request,'auth/signup.html')
        try:
            if User.objects.get(username=email):
                messages.warning(request,"Email is Taken")
                return render(request,'auth/signup.html')
        except Exception as identifier:
            pass
        user = User.objects.create_user(email,email,password)
        user.is_active = False
        user.save()
        messages.info(request,"Activate Your Account by clicking on link your mail")
        activateEmail(request,user,email)
        return redirect('/EComAuth/login/')
    return render(request,'auth/signup.html')


def Login(request):
    if request.method == 'POST':
        # get parameters
        loginusername=request.POST['email']
        loginpassword=request.POST['pass1']
        user=authenticate(username=loginusername,password=loginpassword)
        if user is not None:
            login(request,user)
            messages.info(request,"Successfully Logged In")
            return redirect('/')
        else:
            messages.error(request,"Invalid Credentials")
            return redirect('/EComAuth/login')    
    return render(request,'auth/login.html') 
def Logout(request):
    logout(request)
    messages.success(request,"Logout Successfully")
    return redirect('/EComAuth/login')

class RequestResetEmailView(View):
    def get(self,request):
        return render(request,'auth/request-reset-email.html/')
    def post(self,request):
        email = request.POST['email']
        user = User.objects.filter(email = email)
        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset Your Password]'
            message = render_to_string('auth/request-reset-password.html',{
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0]),
                # "protocol": 'https' if request.is_secure() else 'http'
            })
            email_msg = EmailMessage(email_subject,message,to = [email])
            EmailThread(email_msg).start()
            messages.info(request,"We have sent you an email with instructions on how to reset the password")
            return render(request,'auth/request-reset-email.html')
class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context = {
            'uidb64' : uidb64,
            'token' : token
        }
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"password Reset Link is Invalid")
                return render(request,'auth/request-reset-email.html')
        except DjangoUnicodeDecodeError as identifier:
            pass
        return render(request,'auth/set-new-password.html',context)
    def post(self,request,uidb64,token):
        context = {
            'uidb64' : uidb64,
            'token' : token
        }
        password = request.POST['pass1']
        conf_password = request.POST['pass2']
        if password != conf_password:
            messages.warning(request,"Password is not Matching")
            return render(request,'auth/set-new-password.html',context)
        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request,"Password Reset Success Please Login with NewPass")
            return redirect('/EcomAuth/login/')
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,"Something Went Wrong")
            return render(request,'auth/set-new-password.html',context)
        #return render(request,'auth/set-new-password.html',context)
        