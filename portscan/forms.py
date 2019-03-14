from django import forms  
from django.forms import ModelForm, inlineformset_factory
from .models import Collect , Ip, Configure, Port


class CollectForm(forms.Form):
    temp_id = forms.CharField()
    class Meta:  
        model = Collect

class IpForm(forms.ModelForm):
    class Meta:
        fields =  "__all__"

class ConfigureForm(forms.Form):
    class Meta:  
        model = Configure
        fields =  "__all__"