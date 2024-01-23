from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from ashrith import settings
from django.core.mail import send_mail,EmailMessage
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponseServerError
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from .tokens import generate_token
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import UserProfileForm

# Create your views here.
def home(request):
    return render(request,"authentication/index.html")

def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username=username):
            messages.error(request,"Username already exists!")
            return redirect('home')
        
        if User.objects.filter(email=email):
            messages.error(request,"Email already Registerd")
            return redirect('home')
        
        if len(username)>10:
            messages.error(request,"Username must be under 10 characters")
            return redirect('home')
        if pass1 != pass2:
            messages.error(request,"Passwords didn't match")

        myuser = User.objects.create_user(username,email,pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()
        messages.success(request,"Your account has been successfully created.We have sent you a confirmation email, please confirm you email to activate your account.")

        # Welcome email
        subject = "Welcome to Dezhvery"
        message = "Hello" + myuser.first_name + "!! \n" + "Welcome to Dezhvery!! \n Thank you for visiting our Website \n We have also sent you a confirmation email, please confirm you email address in order to activate your account.\n \n Thanking You \n Ashrith"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email,to_list,fail_silently=True)
        # try:
        #     send_mail(subject, message, from_email, to_list, fail_silently=False)
        # except BadHeaderError:
        #     return HttpResponseServerError('Invalid header found.')
        # except Exception as e:
        #     messages.error(request, f"An error occurred while sending the welcome email: {e}")
        # return redirect('home')


        #email address confirmation email
        current_site = get_current_site(request)
        email_subject = "Confirm your email @ Devzery - Django Login!!"
        message2 = render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        send_mail(email_subject, message2, from_email, to_list, fail_silently=True)
        return redirect('signin')

    return render(request,"authentication/signup.html")

def signin(request):
    if request.method == "POST":
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username,password=pass1)

        if user is not None:
            login(request,user)
            fname = user.first_name
            return render(request,"authentication/index.html",{'fname':fname})
        else:
            messages.error(request,"Wrong Credential")
            return redirect('home')
    return render(request,"authentication/signin.html")

def signout(request):
    logout(request)
    messages.success(request,"Logged out successfully!")
    return redirect('home')

def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        messages.success(request, "Your account has been activated!")
        return redirect('signin')
    else:
        return render(request, 'activation_failed.html')
    

@login_required
def manage_profile(request):
    users = User.objects.exclude(id=request.user.id).values('username')
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('manage_profile')
        else:
            messages.error(request, 'Error updating your profile. Please check the form.')
    else:
        form = UserProfileForm(instance=request.user)
    
    return render(request, 'authentication/manageprofile.html', {'form': form, 'users': users})