import copy

from django.conf import settings
from django.utils.translation import gettext as _
from saml2.metadata import entity_descriptor
from saml2.config import IdPConfig
from saml2.server import Server
from .models import ServiceProvider

class IDP:
    _server_instance: Server = None
    
    @classmethod
    def construct_metadata(cls) -> dict:
        idp_config = copy.deepcopy(settings.SAML_IDP_CONFIG)
        if idp_config:
            idp_config['metadata'] = {
                'local': [sp.metadata_path() for sp in ServiceProvider.objects.filter(active=True)]
            }
        return idp_config
    
    @classmethod
    def load(cls, force_refresh:bool = False) -> Server:
        if cls._server_instance is None or force_refresh:
            conf = IdPConfig() #
            md = cls.construct_metadata() #
            try:
                conf.load(md)
                cls._server_instance = Server(config=conf)
            except :
                pass
        return cls._server_instance
    
    @classmethod
    def metadata(cls) -> str:
        conf = IdPConfig()
        try:
            conf.load(cls.construct_metadata())
            metadata = entity_descriptor(conf)
        except:
            pass
        return str(metadata)
                