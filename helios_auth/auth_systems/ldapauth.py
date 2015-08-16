"""
LDAP Authentication
Author : shirlei@gmail.com
Version: 1.0
Requires libldap2-dev
django-auth-ldap 1.2.6

"""

from django import forms
from django.conf import settings
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect


from helios_auth.auth_systems.ldapbackend import backend


# some parameters to indicate that status updating is possible
STATUS_UPDATES = False


LOGIN_MESSAGE = "Log in with my LDAP Account"

class LoginForm(forms.Form):
    username = forms.CharField(max_length=250)
    password = forms.CharField(widget=forms.PasswordInput(), max_length=100)
    
    
def ldap_login_view(request):
    from helios_auth.view_utils import render_template
    from helios_auth.views import after
    
    error = None
    
    if request.method == "GET":
            form = LoginForm()
    else:
            form = LoginForm(request.POST)
            
            request.session['auth_system_name'] = 'ldap'

            if request.POST.has_key('return_url'):
                request.session['auth_return_url'] = request.POST.get('return_url')
                
            if form.is_valid():
                username = form.cleaned_data['username'].strip() 
                password = form.cleaned_data['password'].strip() 

                auth = backend.CustomLDAPBackend()
                user = auth.authenticate(username, password)
                
                if user:
                    request.session['ldap_user']  = {
                        'user_id': user.email,
                        'name': user.first_name + ' ' + user.last_name,
                    }
                    return HttpResponseRedirect(reverse(after))
                else:
                    error = 'Bad Username or Password'

    return render_template(request, 'password/login', {
            'form': form,
            'error': error,
            'enabled_auth_systems': settings.AUTH_ENABLED_AUTH_SYSTEMS,
        })
    

def get_user_info_after_auth(request):   
    return {
       'type': 'ldap', 
       'user_id' : request.session['ldap_user']['user_id'], 
       'name': request.session['ldap_user']['name'], 
       'info': {'email': request.session['ldap_user']['user_id']}, 
       'token': None 
    }


def get_auth_url(request, redirect_url = None):
    return reverse(ldap_login_view)


def send_message(user_id, name, user_info, subject, body):
    send_mail(subject, body, settings.SERVER_EMAIL, ["%s <%s>" % (name, user_id)], fail_silently=False)


def check_constraint(constraint, user_info):
    """
    for eligibility
    """
    pass
