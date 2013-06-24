# Create your views here.

import requests
import urllib
import urllib2
import json

from django.views.decorators.csrf import csrf_exempt

from django.contrib.auth.models import User
from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import login, authenticate, logout
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.template import RequestContext
from django.shortcuts import render_to_response, get_object_or_404


from parse_rest.datatypes import Object as ParseObject
from parse_rest.user import User as ParseUser


from google.models import Device, GlassUser, Notification, TimelineAttachment


authenticate_url = 'https://accounts.google.com/o/oauth2/auth'
access_token_url = 'https://accounts.google.com/o/oauth2/token'


def index(request):

    return render_to_response('index.html', {},
                                    context_instance=RequestContext(request))


def get_new_access_token(refresh_token):

    data = 'client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s' % (settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET, refresh_token)

    headers = {'content-type' : 'application/x-www-form-urlencoded'}
    r = requests.post(access_token_url, headers=headers, data=data)

    #print r.json()

    return r.json()['access_token']


def google_login(request):

    next = request.GET.get('next', None)
    if next:
        request.session['google_login_next'] = next
    
    scope = urllib.quote('https://www.googleapis.com/auth/userinfo#email https://www.googleapis.com/auth/glass.timeline')
    url = '%s?client_id=%s&response_type=code&scope=%s&access_type=offline&redirect_uri=%s%s' % (authenticate_url, settings.GOOGLE_CLIENT_ID, scope, settings.DOMAIN, reverse('callback'))

    return HttpResponseRedirect(url)

    
def google_callback(request):

    code = request.GET.get('code','')

    domain = settings.DOMAIN

    redirect_uri = urllib2.quote('%s%s' % (domain, reverse('callback')))
    
    data = 'client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=%s' % (settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET, code, redirect_uri)

    req = urllib2.Request(access_token_url, data=data)
    response = urllib2.urlopen(req)
    response_content = response.read()

    json_response = simplejson.loads(response_content)

    access_token = json_response['access_token']

    refresh_token = None
    if 'refresh_token' in json_response:
        refresh_token = json_response['refresh_token']

    #import ipdb; ipdb.set_trace()

    email = get_email(access_token)

    users = GlassUser.Query.all().eq(email=email)

    if users.count() == 0:
        user = GlassUser(email=email)
        user.token = User.objects.make_random_password(length=16) 
    else:
        for item in users:
            user = item

    user.access_token = access_token
    if refresh_token:
        user.refresh_token = refresh_token
    user.save()

    create_contact(access_token)

    subscription_id = create_subscription(access_token, email)
    user.subscription_id = subscription_id
    user.save()

    return HttpResponseRedirect('/signed_up')


def signed_up(request):

    return render_to_response('signed_up.html', {},
                                    context_instance=RequestContext(request))



def create_contact(access_token):

    base_url = 'https://www.googleapis.com/mirror/v1/contacts/'

    url = '%s%s' % (base_url, settings.GLASS_CONTACT_ID)

    params = {'access_token' : access_token}

    r = requests.get(url, params=params)

    json_response = r.json()

    already_exists = False
    if 'error' in json_response:
        #already exists
        url = base_url
    else:
        already_exists = True

    payload = { "id": settings.GLASS_CONTACT_ID
        , "displayName": settings.GLASS_CONTACT_DISPLAY_NAME
        , "imageUrls": ["https://lh5.googleusercontent.com/-UPH5FjmGJk8/UJQ5txO-J2I/AAAAAAAAPH0/tb33B_0Xlhg/w460-h613-no/IMG_20121102_142125.jpg"]
        , "acceptTypes" : ['image/jpeg', 'image/png']
    }

    headers = {'content-type': 'application/json'
            , 'Authorization' : 'Bearer %s' % access_token}


    if already_exists:
        r = requests.put(url, data=json.dumps(payload), headers=headers)
    else:
        r = requests.post(url, data=json.dumps(payload), headers=headers)


def create_subscription(access_token, email):

    base_url = 'https://www.googleapis.com/mirror/v1/subscriptions'

    url = base_url

    payload = {'collection' : 'timeline'
        , 'userToken' : email
        , 'operation' : ['INSERT', 'UPDATE']
        , 'callbackUrl' : settings.GLASS_SUBSCRIPTION_CALLBACK_URL }

    headers = {'content-type': 'application/json'
            , 'Authorization' : 'Bearer %s' % access_token}

    r = requests.post(url, data=json.dumps(payload), headers=headers)

    return r.json()['id']


@csrf_exempt
def google_receive(request):

    if not request.body:
        notification = Notification(email="testing")
        notification.save()
        return HttpResponse('error')

    json_response = simplejson.loads(request.body)

    timeline_id = json_response['itemId']
    email = json_response['userToken']

    notification = Notification(email=email)
    notification.save()

    users = GlassUser.Query.all().eq(email=email)

    user = None
    for item in users:
        user = item

    if not user:
        return HttpResponse('error')

    access_token = get_new_access_token(user.refresh_token)

    url = 'https://www.googleapis.com/mirror/v1/timeline/%s/?access_token=%s' % (timeline_id, access_token)

    r = requests.get(url) 
    
    json_response = r.json()

    if 'attachments' in json_response and len(json_response['attachments']) > 0:
        attachment_id = json_response['attachments'][0]['id']
    else:
        return HttpResponse('error')


    attachment_exists = TimelineAttachment.Query.all().where(timeline_id=timeline_id, attachment_id=attachment_id, email=email).count() > 0

    if not attachment_exists:
        attachment = TimelineAttachment(timeline_id=timeline_id, attachment_id=attachment_id, email=email)
        attachment.save()

    #import ipdb; ipdb.set_trace()

    devices = Device.Query.all().eq(email=email)  

    for device in devices:
        response = send_notification(device.gcm_registration_id, timeline_id, attachment_id)
        notification.response = response
        notification.save()


    #import ipdb; ipdb.set_trace()

    return HttpResponse('done')



def send_notification(registration_id, timeline_id, attachment_id):

    #import ipdb; ipdb.set_trace()

    url = 'https://android.googleapis.com/gcm/send'

    payload = {'registration_ids' : [registration_id], 'data' : {'timeline_id' : timeline_id, 'attachment_id' : attachment_id}}
    headers = {'content-type' : 'application/json', 'Authorization' : 'key=%s' % settings.GOOGLE_API_KEY}

    #print headers

    r = requests.post(url, headers=headers, data=json.dumps(payload))

    return r.text

    #print r.json()



def get_access_token(request):

    user_token = request.GET.get('token', None)

    if not user_token:
        return HttpResponse('error')

    users = GlassUser.Query.all().eq(token=user_token)

    user = None
    for item in users:
        user = item

    if not user:
        return HttpResponse('error')

    access_token = get_new_access_token(user.refresh_token)

    response_dict = {}
    response_dict['access_token'] = access_token

    return HttpResponse(simplejson.dumps(response_dict))


def get_email(access_token):

    user_info_url = 'https://www.googleapis.com/userinfo/email?alt=json'
    req = urllib2.Request(user_info_url)
    req.add_header("Authorization", "OAuth %s" % access_token)
    response = urllib2.urlopen(req)
    response_content = response.read()
    json_response = simplejson.loads(response_content)
    email = json_response['data']['email']
    return email


def get_user_info(access_token):

    plus_user_info_url = 'https://www.googleapis.com/plus/v1/people/me/?access_token=%s' % access_token

    response = requests.get(plus_user_info_url)

    json_response = json.loads(response.content)

    return json_response





 
