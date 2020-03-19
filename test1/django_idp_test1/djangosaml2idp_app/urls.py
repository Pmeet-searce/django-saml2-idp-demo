from django.urls import path
from .views import SSOInitView,sso_entry,LoginProcessView,LogoutProcessView,metadata

app_name = 'djangosaml2idp_app' 

urlpatterns = [
    path('sso/init/', SSOInitView.as_view(), name="saml_idp_init"),
    path('sso/<str:binding>/',sso_entry, name="saml_login_binding"),
    path('login/process/', LoginProcessView.as_view(), name="saml_login_process"),
    path('slo/<str:binding>/', LogoutProcessView.as_view(), name="saml_logout_binding"),
    path('metadata/',metadata, name='saml2_idp_metadata'),
    
]
