from django import forms
from django.utils.translation import gettext as _

from django.contrib.auth.models import User
from socialregistration.signals import socialregistrationuser_created

from signup_codes.models import check_signup_code #SignupCode
from programs.middleware import get_current_program


class UserForm(forms.Form):
    username = forms.RegexField(r'^\w+$', max_length=32)
    email = forms.EmailField(required=False)

    def __init__(self, user, profile, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.user = user
        self.profile = profile

    def clean_username(self):
        username = self.cleaned_data.get('username')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return username
        else:
            raise forms.ValidationError(_('This username is already in use.'))

    def save(self, request=None):
        self.user.username = self.cleaned_data.get('username')
        self.user.email = self.cleaned_data.get('email')
        self.user.save()
        self.profile.user = self.user
        self.profile.save()
        socialregistrationuser_created.send( 
                        sender=None, 
                        user=self.user, 
                        profile=self.profile, 
                        request=request)
        return self.user


class FacebookUserForm(forms.Form):
    #username = forms.RegexField(r'^\w+$', max_length=32)
    email = forms.EmailField(required=True)

    def __init__(self, user, profile, *args, **kwargs):
        super(FacebookUserForm, self).__init__(*args, **kwargs)
        self.user = user
        self.profile = profile

        # my hack - no need for sign up code if they are in a program
        if get_current_program():
            self.fields['signup_code'] = forms.CharField(max_length=40, required=False, widget=forms.widgets.HiddenInput())
        else:
            self.fields['signup_code'] = forms.CharField(max_length=40, required=False, widget=forms.PasswordInput(),
                                label=_("Signup Code"))
 

    def clean_email(self):
        email = self.cleaned_data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return email
        else:
            raise forms.ValidationError(_('This email is already in use.'))

    def save(self, request=None):
        self.user.email = self.cleaned_data.get('email')
        self.user.save()
        self.profile.user = self.user
        self.profile.save()
        socialregistrationuser_created.send( 
                        sender=None, 
                        user=self.user, 
                        profile=self.profile, 
                        request=request)
        return self.user

    def clean_signup_code(self):
        code = self.cleaned_data.get("signup_code")

        # my hack - no need to use signup if they are in a program
        if get_current_program():
            signup_code = True
        else:
            signup_code = check_signup_code(code)

        if signup_code:
            return signup_code
        else:
            raise forms.ValidationError("Signup code was not valid.")


