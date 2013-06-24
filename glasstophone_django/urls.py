from django.conf.urls import patterns, include, url
from django.conf import settings


from parse_rest.connection import register as parse_register
parse_register(settings.PARSE_APPLICATION_ID, settings.PARSE_REST_API_KEY, master_key=settings.PARSE_MASTER_KEY)



urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'glasstophone.views.home', name='home'),
    # url(r'^glasstophone/', include('glasstophone.foo.urls')),
    url(r'^$', 'google.views.index'),
    url(r'^login/$', 'google.views.google_login', name='login'),
    url(r'^callback/$', 'google.views.google_callback', name="callback"),
    url(r'^signed_up/$', 'google.views.signed_up', name="signed_up"),
    url(r'^receive/$', 'google.views.google_receive', name="receive"),
    url(r'^get_access_token/$', 'google.views.get_access_token', name="get_access_token"),
    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
