from django.db import models
from django.contrib.auth import get_user_model
from saml2 import xmldsig
from .utils import (extract_validuntil_from_metadata, fetch_metadata, validate_metadata)
from .idp import IDP
from .processors import validate_processor_path,instantiate_processor
from django.conf import settings
from django.utils.functional import cached_property
from django.utils.timezone import now
from typing import Dict

import datetime
import pytz
import json
import os

# Create your models here.
# class User(models.Model):
    
#     username= models.CharField(max_length=250)
#     password=models.CharField(max_length=20)
    
#     def __str__(self):
#         return self.username

User = get_user_model()

default_attribute_mapping = {
    'email' : 'email',
    'first_name' : 'first_name',
    'last_name' : 'last_name',
    'is_staff' : 'is_staff',
    'is_superuser' : 'is_superuser',
}

class ServiceProvider(models.Model):
    dt_created = models.DateTimeField(auto_now_add=True)
    dt_updated = models.DateTimeField(auto_now=True,null=True,blank=True)
    
    #indentification of SP
    entity_id = models.CharField(max_length=256,unique=True)
    description = models.TextField(blank=True)
    
    #metadata
    metadata_expiration_dt = models.DateTimeField()
    remote_metadata_url = models.CharField(max_length=512,blank=True)
    local_metadata = models.TextField(blank=True)
    
    # def refresh_metadata
    
    #configuration
    
    active  = models.BooleanField(default=True)
    
    _processor = models.CharField(max_length=256,default='djangosaml2idp_app.processors.BaseProcessor')
    
    _attribute_mapping = models.TextField(default=json.dumps(default_attribute_mapping))
    
    _nameid_field = models.CharField(blank=True,max_length=64)
    
    _sign_response = models.BooleanField(blank=True, null=True)
    
    _sign_assertion = models.BooleanField(blank=True,null=True)
    
    _signing_algorithm = models.CharField(blank=True, null=True,max_length=256, choices = [(constant, pretty) for (pretty, constant) in xmldsig.SIG_ALLOWED_ALG])  # xmldsig.SIG_ALLOWED_ALG
    
    _digest_algorithm = models.CharField(blank=True, null=True, max_length=256, choices = [(constant, pretty) for (pretty, constant) in xmldsig.DIGEST_ALLOWED_ALG]) # xmldsig.DIGEST_ALLOWED_ALG
    
    _encrypt_saml_responses = models.BooleanField(null=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['entity_id', ]),
        ]
        
    def __str__(self):
        return self.entity_id    
    
    def save(self, *args, **kwargs):
        if not self.metadata_expiration_dt:
            self.metadata_expiration_dt = extract_validuntil_from_metadata(self.local_metadata).replace(tzinfo=None) # tzinfo=None
        super().save(*args,**kwargs)
        IDP.load(force_refresh=True)
        
    def refresh_metadata(self, force_refresh:bool = False) -> bool:
        if not self.local_metadata or not self.metadata_expiration_dt or now() > self.metadata_expiration_dt or force_refresh:
            if self.remote_metadata_url:
                try:
                    self.local_metadata = validate_metadata(fetch_metadata(self.remote_metadata_url))
                except:
                    pass
            elif self.metadata_expiration_dt and now( > self.metadata_expiration_dt):
                pass
            self.metadata_expiration_dt=extract_validuntil_from_metadata(self.local_metadata)
            return True
        return False
            
    @property
    def attribute_mapping(self) -> Dict(str,str):
        if not self._attribute_mapping:
            return default_attribute_mapping
        return json.loads(self._attribute_mapping)
    
    @property
    def nameid_field(self) -> str:
        if self._nameid_field:
            return self._nameid_field
        if hasattr(settings, 'SAML_IDP_DJANGO_USERNAME_FIELD'): #
            return settings.SAML_IDP_DJANGO_USERNAME_FIELD #
        return getattr(User,'USERNAME_FIELD','username') #
    
    @cached_property
    def processor(self) -> 'BaseProcessor':
        processor_cls = validate_processor_path(self._processor)
        return instantiate_processor(processor_cls, self.entity_id)
    
    def metadata_path(self) -> str:
        
        refreshed_metadata = self.refresh_metadata()
        if refreshed_metadata:
            self.save()
        
        path='tmp/djangosaml2idp'
        
        if not os.path.exists(path):
            try:
                os.mkdir(path)
            except:
                pass
        filename = '{}/{}.xml'.format(path,self.id)
        
        if not os.path.exists(filename) or refreshed_metadata or self.dt_updated.replace(tzinfo=pytz.utc) > datetime.datetime.fromtimestamp(os.path.getmtime(filename)).replace(tzinfo=pytz.utc):
            try:
                with.open(filename, 'w') as f:
                    f.write(self.local_metadata)
            except:
                raise
            return filename
        
        
    @property
    def sign_response(self) -> bool:
        if self._sign_assertion is None:
            return getattr(IDP.load().config,"sign_response",False)
        return self._sign_response
    
    @property
    def sign_assertion(self) -> bool:
        if self._sign_assertion is None:
            return getattr(IDP.load().config,"sign_assertion", False)
        return self._sign_assertion
    
    @property
    def encrypt_saml_responses(self) -> bool:
        if self._encrypt_saml_responses is None:
            return getattr(settings, 'SAML_ENCRYPT_AUTHN_RESPONSE', False)
        return self._encrypt_saml_responses
    
    @property
    def signing_algorithm(self) -> str:
        if self._signing_algorithm is None:
            return getattr(settings, 'SAML_AUTHN_SIGN_ALG', xmldsig.SIG_RSA_SHA256)
        return self._signing_algorithm
    
    @property
    def digest_algorithm(self) -> str:
        if self._digest_algorithm is None:
            return getattr(settings,'SAML_AUTHN_DIGEST_ALG', xmldsig.DIGEST_SHA256)
        return self._digest_algorithm
    
    @property
    def resulting_config(self) -> str:
        try:
            d = {
                'entity_id':self.entity_id,
                'attribute_mapping':self.attribute_mapping,
                'nameid_field':self.nameid_field,
                'sign_response':self.sign_response,
                'sign_assertion':self.sign_assertion,
                'encrypt_saml_responses':self.encrypt_saml_responses,
                'signing_algorithm': self.signing_algorithm,
                'digest_algorithm': self.diIN

        except:
            pass
        
        return mark_safe(config_as_str.replace("\n", "<br>").replace(" ","&nbsp;&nbsp;&nbsp;&nbsp;"))
    
            
        
    
    
    
        
    
        
        
        
        
        
        
        
        
        