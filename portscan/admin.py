from __future__ import unicode_literals
from django.contrib import admin
from .models import Collect, Ip, Port, Configure
# Register your models here.
class CollectmodelAdmin(admin.ModelAdmin):
    list_filter = ['name',]
    list_display = ['name']

class IpmodelAdmin(admin.ModelAdmin):
    list_filter = ['ip',]
    list_display = ['ip']

class PortmodelAdmin(admin.ModelAdmin):
    list_filter = ['port',]
    list_display = ['port']

admin.site.register(Collect, CollectmodelAdmin)
admin.site.register(Ip, IpmodelAdmin)
admin.site.register(Port, PortmodelAdmin)