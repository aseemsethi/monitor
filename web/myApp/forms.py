from django.forms import ModelForm
from myApp.models import cfg


class cfgForm(ModelForm):
    class Meta:
        model = cfg
        fields = '__all__'

