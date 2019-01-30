from import_export import resources
from .models import Ip

class IpResource(resources.ModelResource):
    class Meta:
        model = Ip