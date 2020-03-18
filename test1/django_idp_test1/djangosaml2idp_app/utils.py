from saml2.response import StatusResponse
from xml.parsers.expat import ExpatError
from django.utils.translation import gettext as _
from django.core.exceptions import ValidationError

import arrow
import requests
import zlib
import xml.etree.ElementTree as ET
import base64
import datetime
import xml.dom.minidom

def repr_saml(saml: str, b64: bool = False):
    try:
        msg = base64.b64decode(saml).decode() if b64 else saml
        dom = xml.dom.minidom.parseString(msg)
    except (UnicodeDecodeError, ExpatError):
        msg = base64.b64decode(saml)
        inflated = zlib.decompress(msg, -15)
        dom = xml.dom.minidom.parseString(inflated.decode())
    return dom.toprettyxml()

def encode_saml(saml_envelope: str, use_zlib: bool = False) -> bytes:
    before_base64 = zlib.compress(saml_envelope.encode())[2:-4] if use_zlib else saml_envelope.encode()
    return base64.b64encode(before_base64)

def verify_request_signature(req_info: StatusResponse) -> None:
    if not req_info.signature_check(req_info.xmlstr):
        raise ValueError(_("Signature verification failed"))

def fetch_metadata(remote_metadata_url: str) -> str:
    try:
        content = requests.get(remote_metadata_url,timeout=(3,10))
        if content.status_code != 200:
            raise Exception("Non-succesful request, received status code {}".format(content.status_code))
    except:
        raise ValidationError("Could not fetch metadata from {}".format(remote_metadata_url))
    return content.text

def validate_metadata(metadata: str) -> str:
    try:
        ET.fromstring(metadata) #
    except:
        pass
    return metadata

def extract_validuntil_from_metadata(metadata: str) -> datetime.datetime:
    try:
        metadata_expiration_dt = arrow.get(ET.fromstring(metadata).attrib['validUntil']).datetime
    except:
        pass
    
    return metadata_expiration_dt

  
