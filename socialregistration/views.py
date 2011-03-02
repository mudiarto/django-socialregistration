
from django.conf import settings
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.utils.translation import gettext as _
from django.http import HttpResponseRedirect

try:
    from django.views.decorators.csrf import csrf_protect
    has_csrf = True
except ImportError:
    has_csrf = False

from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout as auth_logout
from django.contrib.sites.models import Site

from socialregistration.forms import UserForm, FacebookUserForm
from socialregistration.utils import (OAuthClient, OAuthTwitter,
    OpenID, _https, DiscoveryFailure)
from socialregistration.models import FacebookProfile, TwitterProfile, OpenIDProfile

from libs.utils import generate_unique_username
from signup_codes.models import SignupCode
from socialregistration.signals import socialregistrationuser_created

from django.core.validators import validate_email, ValidationError
#from django.db.models import EmailField

FB_ERROR = _('We couldn\'t validate your Facebook credentials')

GENERATE_USERNAME = bool(getattr(settings, 'SOCIALREGISTRATION_GENERATE_USERNAME', False))




def _get_next(request):
    """
    Returns a url to redirect to after the login
    """
    if 'next' in request.session:
        next = request.session['next']
        del request.session['next']
        return next
    elif 'next' in request.GET:
        return request.GET.get('next')
    elif 'next' in request.POST:
        return request.POST.get('next')
    else:
        return getattr(settings, 'LOGIN_REDIRECT_URL', '/')

def valid_email_or_none(email):
    # email validation & check length
    if email:
        try:
            validate_email(email)
            #if len(email) > EmailField().max_length:
            if len(email) > 255:   # my hack, see base/models - hack_email()
                email = None
        except ValidationError:
            pass

    # check if email already exists
    if email:
        try:
            user = User.objects.get(email=email)
            email = None # user with this email already exists, set email to None
        except User.DoesNotExist:
            pass

    return email


def setup(request, template='socialregistration/setup.html',
    form_class=UserForm, extra_context=dict()):
    """
    Setup view to create a username & set email address after authentication
    """
    try:
        social_user = request.session['socialregistration_user']
        social_profile = request.session['socialregistration_profile']
    except KeyError:
        return render_to_response(
            template, dict(error=True), context_instance=RequestContext(request))

    if not GENERATE_USERNAME:
        # User can pick own username
        if not request.method == "POST":
            form = form_class(social_user, social_profile)
        else:
            form = form_class(social_user, social_profile, request.POST)

            if form.is_valid():

                form.save(request=request)
                user = form.profile.authenticate()
                login(request, user)

                del request.session['socialregistration_user']
                del request.session['socialregistration_profile']

                return HttpResponseRedirect(_get_next(request))

        extra_context.update(dict(form=form))

        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))

    else:
        # Generate user and profile
        social_user.username = generate_unique_username()
        social_user.save()

        social_profile.user = social_user
        social_profile.save()

        # Authenticate and login
        user = social_profile.authenticate()
        login(request, user)

        # Clear & Redirect
        del request.session['socialregistration_user']
        del request.session['socialregistration_profile']
        return HttpResponseRedirect(_get_next(request))

if has_csrf:
    setup = csrf_protect(setup)



def facebook_setup(request, template='socialregistration/facebook_setup.html',
    form_class=FacebookUserForm, extra_context=dict()):
    """
    Setup view to create a username & set email address after authentication
    Clone of setup, special to do facebook stuff

    TODO:
        need to handle this scenario :
            - user logged in with facebook, but the email already exists - somewhat handled correctly right now,
              although not very convenient
    """
    try:
        social_user = request.session['socialregistration_user']
        social_profile = request.session['socialregistration_profile']
    except KeyError:
        return render_to_response(
            template, dict(error=True), context_instance=RequestContext(request))

    if not GENERATE_USERNAME or (not social_user.email):
        # Should go here so user can pick their email
        if not request.method == "POST":
            form = form_class(social_user, social_profile)
        else:
            social_user.username = generate_unique_username()
            form = form_class(social_user, social_profile, request.POST)

            if form.is_valid():
                form.save(request=request)
                user = form.profile.authenticate()
                login(request, user)

                signup_code = form.cleaned_data.get("signup_code", None)
                if type(signup_code) == type(SignupCode()):
                    signup_code.use(user)

                del request.session['socialregistration_user']
                del request.session['socialregistration_profile']

                return HttpResponseRedirect(_get_next(request))

        extra_context.update(dict(form=form))
        extra_context['user']=social_user
        extra_context['original_email']=request.session['socialregistration_email']

        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))

    else:
        # Generate user and profile
        social_user.username = generate_unique_username()
        social_user.save()

        social_profile.user = social_user
        social_profile.save()

        socialregistrationuser_created.send( 
                        sender=None, 
                        user=social_user, 
                        profile=social_profile, 
                        request=request)


        # Authenticate and login
        user = social_profile.authenticate()
        login(request, user)

        # Clear & Redirect
        del request.session['socialregistration_user']
        del request.session['socialregistration_profile']
        del request.session['socialregistration_email']
        return HttpResponseRedirect(_get_next(request))

if has_csrf:
    setup = csrf_protect(setup)


def facebook_login(request, template='socialregistration/facebook.html',
    extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
    """
    View to handle the Facebook login
    """

    if request.facebook.uid is None:
        extra_context.update(dict(error=FB_ERROR))
        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))

    user = authenticate(uid=request.facebook.uid)

    if user is None:
        # get facebook graph
        user = User()
        try:
            graph = request.facebook.graph
            profile = graph.get_object("me")
            user.first_name = profile['first_name']
            user.last_name = profile['last_name']
            user.email = valid_email_or_none(profile.get('email'))
        except:
            pass
        request.session['socialregistration_user'] = user
        request.session['socialregistration_profile'] = FacebookProfile(uid=request.facebook.uid)
        request.session['next'] = _get_next(request)
        request.session['socialregistration_email'] = profile.get('email')
        return HttpResponseRedirect(reverse('socialregistration_facebook_setup'))

    if not user.is_active:
        return render_to_response(account_inactive_template, extra_context,
            context_instance=RequestContext(request))

    login(request, user)

    return HttpResponseRedirect(_get_next(request))

def facebook_connect(request, template='socialregistration/facebook.html',
    extra_context=dict()):
    """
    View to handle connecting existing django accounts with facebook
    """
    if request.facebook.uid is None or request.user.is_authenticated() is False:
        extra_context.update(dict(error=FB_ERROR))
        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))

    try:
        profile = FacebookProfile.objects.get(uid=request.facebook.uid)
    except FacebookProfile.DoesNotExist:
        profile = FacebookProfile.objects.create(user=request.user,
            uid=request.facebook.uid)

    return HttpResponseRedirect(_get_next(request))

def logout(request, redirect_url=None):
    """
    Logs the user out of django. This is only a wrapper around
    django.contrib.auth.logout. Logging users out of Facebook for instance
    should be done like described in the developer wiki on facebook.
    http://wiki.developers.facebook.com/index.php/Connect/Authorization_Websites#Logging_Out_Users
    """
    auth_logout(request)

    url = redirect_url or getattr(settings, 'LOGOUT_REDIRECT_URL', '/')

    return HttpResponseRedirect(url)

def twitter(request, account_inactive_template='socialregistration/account_inactive.html',
    extra_context=dict()):
    """
    Actually setup/login an account relating to a twitter user after the oauth
    process is finished successfully
    """
    client = OAuthTwitter(
        request, settings.TWITTER_CONSUMER_KEY,
        settings.TWITTER_CONSUMER_SECRET_KEY,
        settings.TWITTER_REQUEST_TOKEN_URL,
    )

    user_info = client.get_user_info()

    if request.user.is_authenticated():
        # Handling already logged in users connecting their accounts
        try:
            profile = TwitterProfile.objects.get(twitter_id=user_info['id'])
        except TwitterProfile.DoesNotExist: # There can only be one profile!
            profile = TwitterProfile.objects.create(user=request.user, twitter_id=user_info['id'])

        return HttpResponseRedirect(_get_next(request))

    user = authenticate(twitter_id=user_info['id'])

    if user is None:
        profile = TwitterProfile(twitter_id=user_info['id'])
        user = User()
        request.session['socialregistration_profile'] = profile
        request.session['socialregistration_user'] = user
        request.session['next'] = _get_next(request)
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    if not user.is_active:
        return render_to_response(
            account_inactive_template,
            extra_context,
            context_instance=RequestContext(request)
        )

    login(request, user)

    return HttpResponseRedirect(_get_next(request))

def oauth_redirect(request, consumer_key=None, secret_key=None,
    request_token_url=None, access_token_url=None, authorization_url=None,
    callback_url=None, parameters=None):
    """
    View to handle the OAuth based authentication redirect to the service provider
    """
    request.session['next'] = _get_next(request)
    client = OAuthClient(request, consumer_key, secret_key,
        request_token_url, access_token_url, authorization_url, callback_url, parameters)
    return client.get_redirect()

def oauth_callback(request, consumer_key=None, secret_key=None,
    request_token_url=None, access_token_url=None, authorization_url=None,
    callback_url=None, template='socialregistration/oauthcallback.html',
    extra_context=dict(), parameters=None):
    """
    View to handle final steps of OAuth based authentication where the user
    gets redirected back to from the service provider
    """
    client = OAuthClient(request, consumer_key, secret_key, request_token_url,
        access_token_url, authorization_url, callback_url, parameters)

    extra_context.update(dict(oauth_client=client))

    if not client.is_valid():
        return render_to_response(
            template, extra_context, context_instance=RequestContext(request)
        )

    # We're redirecting to the setup view for this oauth service
    return HttpResponseRedirect(reverse(client.callback_url))

def openid_redirect(request):
    """
    Redirect the user to the openid provider
    """
    request.session['next'] = _get_next(request)
    request.session['openid_provider'] = request.GET.get('openid_provider')

    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            Site.objects.get_current().domain,
            reverse('openid_callback')
        ),
        request.GET.get('openid_provider')
    )
    try:
        return client.get_redirect()
    except DiscoveryFailure:
        request.session['openid_error'] = True
        return HttpResponseRedirect(settings.LOGIN_URL)

def openid_callback(request, template='socialregistration/openid.html',
    extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
    """
    Catches the user when he's redirected back from the provider to our site
    """
    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            Site.objects.get_current().domain,
            reverse('openid_callback')
        ),
        request.session.get('openid_provider')
    )

    if client.is_valid():
        identity = client.result.identity_url
        if request.user.is_authenticated():
            # Handling already logged in users just connecting their accounts
            try:
                profile = OpenIDProfile.objects.get(identity=identity)
            except OpenIDProfile.DoesNotExist: # There can only be one profile with the same identity
                profile = OpenIDProfile.objects.create(user=request.user,
                    identity=identity)

            return HttpResponseRedirect(_get_next(request))

        user = authenticate(identity=identity)
        if user is None:
            request.session['socialregistration_user'] = User()
            request.session['socialregistration_profile'] = OpenIDProfile(
                identity=identity
            )
            return HttpResponseRedirect(reverse('socialregistration_setup'))

        if not user.is_active:
            return render_to_response(
                account_inactive_template,
                extra_context,
                context_instance=RequestContext(request)
            )

        login(request, user)
        return HttpResponseRedirect(_get_next(request))

    return render_to_response(
        template,
        dict(),
        context_instance=RequestContext(request)
    )
