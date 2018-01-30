from django.conf.urls import url
import googleauth.views

urlpatterns = [
    url(r'^login/$', googleauth.views.login, name='googleauth_login'),
    url(r'^callback/$', googleauth.views.callback, name='googleauth_callback'),
    url(r'^logout/$', googleauth.views.logout, name='googleauth_logout'),
]
