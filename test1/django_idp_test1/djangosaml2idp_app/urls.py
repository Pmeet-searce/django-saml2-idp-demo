from django.urls import path
from . import views

app_name = 'djangosaml2idp_app' 

urlpatterns = [
    path('sso/init/', views.SSOInitView.as_view(), name="saml_idp_init"),
    path('sso/<str:binding>/',views.sso_entry, name="saml_login_binding"),
    path('login/process/', views.LoginProcessView.as_view(), name="saml_login_process"),
    path('slo/<str:binding>/', views.LogoutProcessView.as_view(), name="saml_logout_binding"),
    path('metadata/',views.metadata, name='saml2_idp_metadata'),
    
]
