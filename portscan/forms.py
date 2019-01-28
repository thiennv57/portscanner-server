from django import forms  
from django.forms import ModelForm, inlineformset_factory
from .models import Collect , Ip, Subnet, Configure, Port


class CollectForm(forms.Form): 
    class Meta:  
        model = Collect  

class IpForm(forms.ModelForm):
    class Meta:
        model = Ip
        fields =  "__all__"


class ConfigureForm(forms.Form):
    class Meta:  
        model = Configure
        fields =  "__all__"

class PortForm(forms.ModelForm):
    class Meta:
        model = Port
        fields =  ('port',)
    def clean(self):
        cleaned_data = super(PortForm, self).clean()
        port = cleaned_data.get('port')
        if not port:
            raise forms.ValidationError('You have to write something!')

SubnetFormSet = inlineformset_factory(
    Collect,
    Subnet,
    form=IpForm,
    extra=3,
    widgets={
        'start_ip': forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ip Adress'
            }
        ),
        'subnetmask': forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Subnet'
            }
        ),
        'end_ip': forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'End Ip'
            }
        )
    }
)
