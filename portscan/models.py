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

    class Meta:
        db_table = "portscan_collect"

    def ips(self):
        return self.ip_set.all()

    def get_absolute_url(self):
        return reverse('collect-update', kwargs={'pk': self.pk})

    def __unicode__(self):
        return "%s %s" % (self.name, self.descripttion)

class Ip(models.Model):
    collect = models.ForeignKey(Collect, on_delete=models.CASCADE)
    ip = models.CharField(max_length=1000)

    class Meta:
        db_table = "portscan_ip"

class Subnet(Ip):
    subnetmask =  models.IntegerField(null=True, blank=True)
    start_ip = models.CharField(max_length=1000, blank=True)
    end_ip = models.CharField(max_length=1000, blank=True)
    excel_file = models.FileField(max_length=1000, blank=True)

class Configure(models.Model):
    scantime = models.IntegerField(unique=True, choices=SCAN_TIMES, default=1)
    email = models.EmailField(blank=True)
    def __unicode__(self):
        return "%s %s" % (self.scantime, self.email)

class Port(models.Model):
    port = models.IntegerField(unique=True)
    port_state = models.ManyToManyField(Ip, through='PortState', through_fields=('port', 'ip'))
    def __unicode__(self):
        return "%s" % (self.port)

    class Meta:
        ordering = ('port',)

class PortState(models.Model):
    ip = models.ForeignKey(Ip, on_delete=models.CASCADE)
    port = models.ForeignKey(Port, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(blank=True)
    last_scan_date = models.DateTimeField(blank=True)

