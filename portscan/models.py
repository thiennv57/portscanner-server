from __future__ import unicode_literals
from django.db import models
from django.conf import settings
import django.utils.safestring as safestring
import datetime
from django.forms import ModelForm
from django.urls import reverse
from netaddr import *
import pprint
import pdb

class Collect(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=1000, blank=True)
    scanday = models.IntegerField(blank=True, default=0)
    scanhour = models.IntegerField(blank=True, default=0)

    def ips(self):
        return self.ip_set.all()

    def get_absolute_url(self):
        return reverse('collect-update', kwargs={'pk': self.pk})

    def __unicode__(self):
        return "%s %s %s" % (self.name, self.descripttion, self.scanday)

    def get_collect_ports(self):
        return self.collectport_set.all().values_list('port', flat=True)

class Ip(models.Model):
    collect = models.ForeignKey(Collect, on_delete=models.CASCADE)
    ip = models.CharField(max_length=1000)
    description = models.CharField(max_length=1000, blank=True)
  
    def open_ports(self):
        return list(PortState.objects.filter(ip_id=self.id, openning=True).order_by('port'))
    def get_ip_ports(self):
        return self.ipport_set.all().values_list('port', flat=True)

class Configure(models.Model):
    scanday = models.IntegerField(unique=True, default=0)
    scanhour = models.IntegerField(unique=True, default=0)
    email = models.EmailField(blank=True)
    def __unicode__(self):
        return "%s" % (self.scanday)

class Port(models.Model):
    port = models.IntegerField(unique=True)
    def __unicode__(self):
        return "%s" % (self.port)

    class Meta: 
        ordering = ('port',)

class PortState(models.Model):
    ip = models.ForeignKey(Ip, on_delete=models.CASCADE)
    port = models.IntegerField()
    openning = models.BooleanField(default=True)
    scan_date = models.DateTimeField(blank=True)
    last_scan_date = models.DateTimeField(blank=True)
    def __unicode__(self):
        return "%s" % (self.port)
    
    def open_ports(self):
        return list(PortState.objects.filter(openning=True).order_by('port'))
    

class IpPort(models.Model):
    ip = models.ForeignKey(Ip, on_delete=models.CASCADE)
    port = models.IntegerField()
    def __unicode__(self):
        return "%s" % (self.port)

class CollectPort(models.Model):
    collect = models.ForeignKey(Collect, on_delete=models.CASCADE)
    port = models.IntegerField()
    class Meta: 
        ordering = ('port',)
    def __unicode__(self):
        return "%s" % (self.port)