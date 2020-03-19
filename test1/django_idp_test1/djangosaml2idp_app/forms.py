from django import forms
from django.utils.translation import gettext as _

from .models import ServiceProvider
from .processors import (instantiate_processor, validate_processor_path)

import json

boolean_form_select_choices = ((None, _('--------')),(True, _('Yes')), (False, _('No')))

class ServiceProviderAdminForm(forms.ModelForm):
    
    class Meta:
        model = ServiceProvider
        fields = '__all__'
        widgets = {
            'encrypt_saml_responses': forms.Select(choices = boolean_form_select_choices),
            '_sign_response': forms.Select(choices = boolean_form_select_choices),
            '_sign_assertion': forms.Select(choices = boolean_form_select_choices),
        }
    
    def clean__attribute_mapping(self):
        value_as_string = self.cleaned_data['_attribute_mapping']
        try:
            value = json.loads(value_as_string)
        except:
            pass
        
        if not isinstance(value,dict):
            pass
        
        for k,v in value.items():
            if not isinstance(k, str) or not isinstance(v, str):
                pass
        return json.dumps(value, indent=4)
    
    def clean__processor(self):
        value = self.cleaned_data['_processor']
        validate_processor_path(value)
        return value
    
    def clean(self):
        cleaned_data = super().clean()
        
        if not(cleaned_data.get('remote_metadata_url')) or cleaned_data.get('local_metadata'):
            print('remote url or local metadata not found')
            pass
        
        if '_processor' in cleaned_data:
            processor_path = cleaned_data['_processor']
            entity_id = cleaned_data['entity_id']
            
            processor_cls = validate_processor_path(processor_path)
            
            instantiate_processor(processor_cls,entity_id)
        
        self.instance.local_metadata = cleaned_data.get('local_metadata')
        
        if cleaned_data.get('remote_metadata_url'):
            self.instance.remote_metadata_url = cleaned_data.get('remote_metadata_url')
            
            cleaned_data['local_metadata'] = self.instance.local_metadata
            
        self.instance.refresh_metadata(force_refresh = True)
        