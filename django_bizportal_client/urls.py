from django.urls import path

from .views import oidc_prepare, oidc_callback, oidc_login, oidc_logout, backchannel_logout, backchannel_event

oidc_urls = [
    path('oidc/prepare/', oidc_prepare, name='oidc_prepare'),
    path('oidc/callback/', oidc_callback, name='oidc_callback'),
    path('oidc/login/', oidc_login, name='oidc_login'),
    path('oidc/logout/', oidc_logout, name='oidc_logout'),
    path('oidc/backchannel-logout/', backchannel_logout, name='oidc_backchannel_logout'),
    path('oidc/backchannel-event/', backchannel_event, name='oidc_backchannel_event'),
]

admin_urls = [
    path('admin/login/', oidc_login, name='admin_login'),
    path('admin/logout/', oidc_logout, name='admin_logout'),
]

default_urls = [
    path('login/', oidc_login, name='login'),
    path('logout/', oidc_logout, name='logout'),
]

urlpatterns = oidc_urls + admin_urls + default_urls
