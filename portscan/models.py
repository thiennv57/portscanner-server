from __future__ import unicode_literals

from django.db import models
from django.conf import settings
import django.utils.safestring as safestring
import datetime
from django.forms import ModelForm
from django.urls import reverse
from django.utils import timezone
from netaddr import *
import pprint

SCAN_TIMES = (
    (1, '1 day'),
    (2, '2 day'),
    (3, '3 day'),
    (4, '4 day'),
    (5, '5 day'),
    (6, '6 day'),
    (7, '7 day'),
    (14, '2 weeks'),
    (21, '3 weeks'),
    (30, '1 month')
)

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

class Ip(models.Model):
    collect = models.ForeignKey(Collect, on_delete=models.CASCADE)
    ip = models.CharField(max_length=1000)
    description = models.CharField(max_length=1000, blank=True)
    def tenth_portstates(self):
        return list(PortState.objects.filter(ip_id=self.id, openning=True))[0:9]
    def eleventh_portstates(self):
        return list(PortState.objects.filter(ip_id=self.id, openning=True))[10:]
    def open_ports(self):
        return list(PortState.objects.filter(ip_id=self.id, openning=True))

class Configure(models.Model):
    scanday = models.IntegerField(unique=True)
    scanhour = models.IntegerField(unique=True)
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
        return list(PortState.objects.filter(openning=True))
    

class IpPort(models.Model):
    ip = models.ForeignKey(Ip, on_delete=models.CASCADE)
    port = models.IntegerField()
    def __unicode__(self):
        return "%s" % (self.port)

class CollectPort(models.Model):
    collect = models.ForeignKey(Collect, on_delete=models.CASCADE)
    port = models.IntegerField()
    def __unicode__(self):
        return "%s" % (self.port)