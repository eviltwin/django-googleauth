from django.urls import re_path
import googleauth.views

urlpatterns = [
    re_path(r'^login/$', googleauth.views.login, name='googleauth_login'),
    re_path(r'^callback/$', googleauth.views.callback, name='googleauth_callback'),
    re_path(r'^logout/$', googleauth.views.logout, name='googleauth_logout'),
]
