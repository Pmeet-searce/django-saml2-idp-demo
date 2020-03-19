from django.shortcuts import render
from django.contrib.auth import get_user_model,logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from django.template.loader import get_template
from django.core.exceptions import (ImproperlyConfigured, ObjectDoesNotExist, PermissionDenied, ValidationError)
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext as _


from saml2 import BINDING_HTTP_POST,BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD, AuthnBroker, authn_context_class_ref
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.ident import NameID


from .models import ServiceProvider 
from .idp import IDP
from .processor import BaseProcessor
from .utils import verify_request_signature


import base64




User = get_user_model()


def store_params_in_session(request: HttpRequest) -> None:
    if request.method == 'POST':
        passed_data = request.POST
        binding = BINDING_HTTP_POST
    else:
        passed_data = request.GET
        binding = BINDING_HTTP_REDIRECT
    
    try:
        saml_request = passed_data['SAMLRequest']
    except:
        pass
    
    request.session['Binding'] = binding
    request.session['SAMLRequest'] = saml_request
    request.session['RelayState'] = passed_data.get('RelayState', '')
    

@never_cache
@csrf_exempt
@require_http_methods(["GET","POST"])
def sso_entry(request: HttpRequest, *args, **kwargs) -> HttpResponse:
    try:
        store_params_in_session(request)
    except:
        pass
    return HttpResponseRedirect(reverse('djangosaml2idp_app:saml_login_process'))

 
# def check_access()

def get_sp_config(sp_entity_id: str) -> ServiceProvider:
    try:
        sp = ServiceProvider.objects.get(entity_id=sp_entity_id,active=True)
    except ObjectDoesNotExist:
        pass
    return sp



def get_authn(req_info=None): 
    req_authn_context = req_info.message.requested_authn_context if req_info else PASSWORD
    broker = AuthnBroker()
    broker.add(authn_context_class_ref(req_authn_context),"")
    return broker.get_authn_by_accr(req_authn_context)

def build_authn_response(user: User, authn, resp_args, service_provider: ServiceProvider) -> list:
    policy = resp_args.get('name_id_policy',None)
    if policy is None:
        name_id_format = NAMEID_FORMAT_UNSPECIFIED
    else: 
        name_id_format = policy.format
    
    idp_server = IDP.load()
    idp_name_id_format_list = idp_server.config.getattr("name_id_format","idp") or [NAMEID_FORMAT_UNSPECIFIED]

    if name_id_format not in idp_name_id_format_list:
        raise ImproperlyConfigured('SP requested a name_id_format that is not supported in the IDP {}'.format(name_id_format))
    
    processor: BaseProcessor = service_provider.processor
    user_id = processor.get_user_id(user,name_id_format,service_provider,idp_server.config)
    
    name_id = NameID(format=name_id_format,sp_name_qualifier=service_provider.entity_id,text=user_id)
    
    return idp_server.create_authn_response(
        authn = authn,
        identity = processor.create_identity(user, service_provider.attribute_mapping),
        name_id = name_id,
        userid = user_id,
        sp_entity_id = service_provider.entity_id,
        sign_response = service_provider.sign_response,
        sign_assertion = service_provider.sign_assertion,
        sign_alg = service_provider.signing_algorithm,
        digest_alg = service_provider.digest_algorightm,
        emcrypt_assertion = service_provider.encrypt_saml_responses,
        encrypted_advice_attributes = service_provider.encrypt_saml_responses,
        **resp_args
    )


class IdPHandlerViewMixin:
    
    def render_login_html_to_string(self, context=None, request=None, using=None):
        
        default_login_template_name = '../templates/djangosaml2idp_app/login.html'
        custom_login_template_name = getattr(self, 'login_html_template', None)
        if custom_login_template_name:
            try:
                template = get_template(custom_login_template_name, using=using)
            except:
                template = get_template(default_login_template_name, using=using)
        else:
            template = get_template(default_login_template_name, using=using)
        return template.render(context, request)

    def create_html_response(self, request: HttpRequest, binding, authn_resp, destination, relay_state):
        
        if binding == BINDING_HTTP_POST:
            context = {
                "acs_url":destination,
                "saml_response": base64.b64encode(str(authn_resp).encode()).decode(),
                "relay_state": relay_state,
            }        
            http_response = {
                  "data": self.render_login_html_to_string(context=context, request=request),
                  "type":"POST",
            }
        else:
            ido_server = IDP.load()
            http_args = ido_server.apply_binding(
                binding = binding,
                msg_str = = authn_resp,
                destination = destination,
                relay_state = relay_state,
                response = True
            )
        html_response = {
            "data": http_args['headers'][0][1],
            "type": "REDIRECT",
        }
        return html_response
    
    def render_response(self, request: HttpRequest, html_response, processor: BaseProcessor = None) -> HttpResponse:
        if not processor:
            if html_response['type'] == 'POST':
                return HttpResponse(html_response['data'])
            else:
                return HttpResponseRedirect(html_response['data'])
        request.session['saml_data'] = html_response

    if html_response['type'] == 'POST':
        return HttpResponse(html_response['data'])
    else:
        return HttpResponseRedirect(html_response['data'])

@method_decorator(never_cache,name = 'dispatch')   
class LoginProcessView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    
    def get(self, request, *args, **kwargs):
        binding = request.session.get('Binding',BINDING_HTTP_POST)
        
        try:
            idp_server = IDP.load()
            
            req_info = idp_server.parse_authn_request(request.session['SAMLRequest'],binding)
            
            try:
                verify_request_signature(req_info)
            except:
                pass
            
            resp_args = idp_server.response_args(req_info.message)
            
            sp_entity_id = resp_args.pop('sp_entity_id')
            service_provider = get_sp_config(sp_entity_id)
            
            try:
                check_access(service_provider.processor, request)
            except:
                pass
            
            authn_resp = =build_authn_response(request.user, get_authn(), resp_args, service_provider)
            
        except:
            pass
        
        html_response = self.create_html_response(
            request,
            binding resp_args['binding'],
            authn_resp = authn_resp,
            destination = resp_args['destination'],
            relay_state = request.session['RelayState']
        )
        
        return self.render_response(request, html_response, service_provider.processor)
   
@method_decorator(never_cache,name = 'dispatch')   
class SSOInitView(LoginRequiredMixin,IdPHandlerViewMixin,View):
    
    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        return self.get(request, *args, **kwargs)
    
    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        passed_data = request.POST or request.GET
        passed_data = passed_data.copy().dict()
        
        try:
            sp_entity_id = passed_data['sp']
            service_provider = get_sp_config(sp_entity_id)
            processor = service_provider.processor
        except:
            pass
        
        try:
            check_access(processor, request)
        except:
            pass
    
        idp_server = IDP.load()
        
        binding_out, destination = idp_server.pick_binding(
            service = "assertion_consumer_service",
            entity_id = sp_entity_id
        )
        
        passed_data['destination'] = destination
        
        passed_data['in_response_to'] = "IdP_Initiated_Login"
        
        authn_resp = build_authn_response(request.user, get_authn(), passed_data, service_provider)
        
        html_response = self.create_html_response(request, binding_out, authn_resp, destination, passed_data.get('RelayState', ""))
        
        return self.render_response(request, html_response, processor)
           

# @method_decorator(never_cache, name='dispatch')
# class ProcessMultiFactorView(LoginProcessView,View):
    
@method_decorator([never_cache, csrf_exempt], name='dispatch')
class LogoutProcessView(LoginRequiredMixin,IdPHandlerViewMixin, View):
    
    __service_name = 'Single Logout'
    
    def post(self, request: HttpRequest, *args, **kwargs):
        return self.get(request, *args, **kwargs)
    
    def get(self, request: HttpRequest, *args, **kwargs):
        store_params_in_session(request)
        binding = request.session['Binding']
        relay_state = request.session['RelayState']

        idp_server = IDP.load()
        
        try:
            req_info = idp_server.parse_logout_request(request.session['SAMLRequest'], binding)
        except:
            pass
        
        try:
            verify_request_signature(req_info)
        except:
            pass
        
        resp = idp_server.create_logout_response(req_info.message, [binding])
        
        try:
            hinfo = idp_server.apply_binding(binding, resp.__str__(),resp.destination, relay_state,response=True)
        except: 
            pass
        
        logout(request)
        
        if hinfo['method'] == 'GET':
            return HttpResponseRedirect(hinfo['headers'][0][1])
        else:
            html_response = self.create_html_response(
                request,
                binding = binding,
                authn_resp = resp.__str__(),
                destination = resp.destination,
                relay_state = relay_state,
            )
        return self.render_response(request,html_response,None)
    
            
@never_cache
def metadata(request: HttpRequest) -> HttpResponse:
    return HttpResponse(content=IDP.metadata().encode('utf-8'),content_type="text/xml; charset=utf8")
