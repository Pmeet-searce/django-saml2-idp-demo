from typing import Dict

from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from django.utils.module_loading import import_string

from saml2.saml import (NAMEID_FORMAT_UNSPECIFIED,NAMEID_FORMAT_TRANSIENT,NAMEID_FORMAT_PERSISTENT,NAMEID_FORMAT_EMAILADDRESS,NAMEID_FORMAT_X509SUBJECTNAME,NAMEID_FORMAT_WINDOWSDOMAINQUALIFIEDNAME,NAMEID_FORMAT_KERBEROS,NAMEID_FORMAT_ENTITY,NAMEID_FORMAT_ENCRYPTED)
from .models import ServiceProvider

import hashlib

User = get_user_model()

class NameIdBuilder:

    format_mappings = {
        NAMEID_FORMAT_UNSPECIFIED: 'get_nameid_unspecified',
        NAMEID_FORMAT_TRANSIENT: 'get_nameid_transient',
        NAMEID_FORMAT_PERSISTENT:'get_nameid_persistent',
        NAMEID_FORMAT_EMAILADDRESS:'get_nameid_email',
        # NOT IMPLEMENTED
        NAMEID_FORMAT_X509SUBJECTNAME:None,
        NAMEID_FORMAT_WINDOWSDOMAINQUALIFIEDNAME:None,
        NAMEID_FORMAT_KERBEROS:None,
        NAMEID_FORMAT_ENTITY:None,
        NAMEID_FORMAT_ENCRYPTED:None
    }
    ##################### I dont know what salt means !!
    @classmethod
    def _get_nameid_opaque(cls, user_id: str, salt: bytes = b'', *args, **kwargs) -> str:
        salted_value = user_id.encode()+ salt
        opaque = hashlib.sha256(salted_value)
        return opaque.hexdigest()
    
    @classmethod
    def get_nameid_persistent(cls, user_id: str, user: User, sp_entityid: str = '', idp_entityid: str = '') -> str:
        return '!'.join([idp_entityid,sp_entityid,cls._get_nameid_opaque(user_id,salt=str(user.pk).encode())])
    
    @classmethod
    def get_nameid_email(cls, user_id: str, **kwargs) -> str:
        if '@' not in user_id:
            raise Exception("Invalid email")
        return user_id
    
    @classmethod
    def get_nameid_transient(cls, user_id: str, **kwargs) -> str:
        raise NotImplementedError('Not implemented yet')
    
    @classmethod
    def get_nameid_unspecified(cls, user_id: str, **kwargs) -> str:
        return user_id
    
    @classmethod
    def get_nameid(cls, user_id: str, nameid_format: str, **kwargs) -> str:
        method = cls.format_mappings.get(nameid_format)
        if not method:
            raise NotImplementedError(" Not mapped in nameidbuilder ")
        if not hasattr(cls, method):
            raise NotImplementedError("Not implemented")
        name_id = getattr(cls, method)(user_id, **kwargs)
        
        return name_id
    
class BaseProcessor:

    def __init__(self, entity_id: str):
        self._entity_id = entity_id
        
    def has_access(self, request) -> bool:
        return True
    
    # def enable_multifactor(self, user) -> bool:
    #     return False
    

    
    def get_user_id(self, user, name_id_format: str, service_provider: ServiceProvider, idp_config) -> bool:
        
        user_field_str = service_provider.nameid_field
        user_field = getattr(user, user_field_str)
        
        if callable(user_field):
            user_id = str(user_field)
        else:
            user_id = str(user_field)
            
        return NameIdBuilder.get_nameid(user_id,name_id_format,sp_entityid = service_provider.entity_id, idp_entityid = idp_config.entityid, user = user)
    
    def create_identity(self, user, sp_attribute_mappings: Dict[str, str]) -> Dict[str, str]:
        results = {}
        for user_attr, out_attr in sp_attribute_mappings.items():
            if hasattr(user, user_attr):
                attr = getattr(user, user_attr)
                results[out_attr] = attr() if callable(attr) else attr 
        return results   
    

def validate_processor_path(processor_class_path: str) -> BaseProcessor:
    try:
        processor_cls = import_string(processor_class_path)
    except:
        pass
    return processor_cls

def instantiate_processor(processor_cls, entity_id: str) -> BaseProcessor:
    try:
        processor_instance = processor_cls(entity_id)
    except:
        pass
    
    if not isinstance(processor_instance, BaseProcessor):
        pass
    
    return processor_instance