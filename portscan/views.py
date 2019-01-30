from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Collect, Ip, Port, Configure, PortState
import pdb

from django.views.generic import CreateView
from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from .forms import CollectForm, IpForm, SubnetFormSet, ConfigureForm, PortForm

from django.urls import reverse_lazy
from django.db import transaction
from django.views.generic import CreateView, UpdateView, DeleteView, ListView, DetailView
from netaddr import *
from string import *
import nmap
import datetime
from django.utils import timezone
from background_task import background
import openpyxl
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template, render_to_string
from django.template import Context

@background(schedule=5)
#Run scan after 5s
def scan_ip():
        scantime_present = datetime.datetime.now()
        nm = nmap.PortScanner()
        ips = Ip.objects.all()
        for ip in ips:
            ports = Port.objects.all()
            for port in ports:
                nm.scan(ip.ip, str(port.port))
                if nm.all_hosts():
                    if nm[str(ip.ip)].tcp(port.port)['state'] == 'open':
                        try:
                            obj = PortState.objects.get(port_id=port.id, ip_id=ip.id)
                            obj.last_scan_date = datetime.datetime.now()
                            obj.save()
                        except PortState.DoesNotExist:
                            obj = PortState(port_id=port.id, ip_id=ip.id, scan_date=datetime.datetime.now(), last_scan_date=datetime.datetime.now())
                            obj.save()
                    else:
                        try:
                            obj = PortState.objects.get(port_id=port.id, ip_id=ip.id)
                            obj.delete()
                        except PortState.DoesNotExist:
                            pass
                else:
                    pass
        print("Send mail!")
        send_email(scantime_present)

def send_email(scantime_present):
    merge_data = {
        'collects': Collect.objects.all,
        'scantime_present': scantime_present
    }

    plaintext_context = Context(autoescape=False)  # HTML escaping not appropriate in plaintext
    subject = 'Scan result report'
    text_body = 'Time: '+str(scantime_present)
    html_body = render_to_string("configure/email.html", merge_data)

    msg = EmailMultiAlternatives(subject=subject, from_email=settings.EMAIL_HOST_USER, to=["nvthien@vnpt.vn"], body=text_body)
    msg.attach_alternative(html_body, "text/html")
    msg.send()

class CollectList(ListView):
    queryset = Collect.objects.all().order_by("name")
    template_name = 'collect/collects.html'
    context_object_name = 'Collects'

class CollectCreate(CreateView):
    model = Collect
    fields = ['name', 'description']

class CollectIpCreate(CreateView):
    model = Collect
    fields = ['name', 'description']
    success_url = reverse_lazy('collects')
    template_name = 'collect/collect_form.html'

    def get_context_data(self, **kwargs):
        data = super(CollectIpCreate, self).get_context_data(**kwargs)
        if self.request.POST:
            data['subnets'] = SubnetFormSet(self.request.POST)
        else:
            data['subnets'] = SubnetFormSet()
        return data

    def form_valid(self, form):
        context = self.get_context_data()
        subnets = context['subnets']
        with transaction.atomic():
            self.object = form.save()
            ip = subnets.data['subnet_set-0-start_ip']
            ip_subnet = subnets.data['subnet_set-1-start_ip']
            subnet = subnets.data['subnet_set-1-subnetmask']
            ip_pool_start = subnets.data['subnet_set-2-start_ip']
            ip_pool_end = subnets.data['subnet_set-2-end_ip']
            collect_id=self.object.id
            
            if ip:
                ips = ip.split(",")
                for ip in ips:
                    ip = ip.strip()
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
            elif ip_subnet:
                for ip in IPNetwork(ip_subnet+str('/')+str(subnet)):
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
            elif ip_pool_start:
                for ip in IPRange(ip_pool_start, ip_pool_end):
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
            elif self.request.FILES["excel_file"]:
                excel_file = self.request.FILES["excel_file"]
                wb = openpyxl.load_workbook(excel_file)
                worksheet = wb["Sheet1"]
                for row in worksheet.iter_rows():
                    for cell in row:
                        cell_data= str(cell.value)
                        if cell_data:
                            if "/" not in cell_data and "-" not in cell_data: 
                                ip = cell_data.strip()
                                try:
                                    obj = Ip.objects.get(ip=ip)
                                except Ip.DoesNotExist:
                                    obj = Ip(collect_id=collect_id, ip=ip)
                                    obj.save()
                            elif "/" in cell_data:
                                for ip in IPNetwork(cell_data):
                                    try:
                                        obj = Ip.objects.get(ip=ip)
                                    except Ip.DoesNotExist:
                                        obj = Ip(collect_id=collect_id, ip=ip)
                                        obj.save()
                            elif "-" in cell_data:
                                pos = (cell_data.find("-"))
                                ip_s = cell_data[:pos]
                                ip_e = cell_data[pos+1:]
                                for ip in IPRange(ip_s, ip_e):
                                    try:
                                        obj = Ip.objects.get(ip=ip)
                                    except Ip.DoesNotExist:
                                        obj = Ip(collect_id=collect_id, ip=ip)
                                        obj.save()
                            else:
                                pass
            else:
                pass
        return super(CollectIpCreate, self).form_valid(form)

class CollectDetail(DetailView): 
    model = Collect
    template_name = 'collect/collect_detail.html'

class CollectUpdate(UpdateView):
    model = Collect
    success_url = '/'
    fields = ['name', 'description']

class CollectIpUpdate(UpdateView):
    model = Collect
    fields = ['name', 'description']
    success_url = reverse_lazy('collects')
    template_name = 'collect/collect_form.html'

    def get_context_data(self, **kwargs):
        data = super(CollectIpUpdate, self).get_context_data(**kwargs)
        if self.request.POST:
            data['subnets'] = SubnetFormSet(self.request.POST, instance=self.object)
        else:
            data['subnets'] = SubnetFormSet(instance=self.object)
        return data

    def form_valid(self, form):
        context = self.get_context_data()
        subnets = context['subnets']
        with transaction.atomic():
            self.object = form.save()
            ip = subnets.data['subnet_set-0-start_ip']
            ip_subnet = subnets.data['subnet_set-1-start_ip']
            subnet = subnets.data['subnet_set-1-subnetmask']
            ip_pool_start = subnets.data['subnet_set-2-start_ip']
            ip_pool_end = subnets.data['subnet_set-2-end_ip']
            collect_id=self.object.id
            if ip:
                ips = ip.split(",")
                for ip in ips:
                    ip = ip.strip()
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
            elif ip_subnet:
                for ip in IPNetwork(ip_subnet+str('/')+str(subnet)):
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
            elif ip_pool_start:
                for ip in IPRange(ip_pool_start, ip_pool_end):
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
            elif self.request.FILES["excel_file"]:
                excel_file = self.request.FILES["excel_file"]
                wb = openpyxl.load_workbook(excel_file)
                worksheet = wb["Sheet1"]
                for row in worksheet.iter_rows():
                    for cell in row:
                        cell_data= str(cell.value)
                        if cell_data:
                            if "/" not in cell_data and "-" not in cell_data: 
                                ip = cell_data.strip()
                                try:
                                    obj = Ip.objects.get(ip=ip)
                                except Ip.DoesNotExist:
                                    obj = Ip(collect_id=collect_id, ip=ip)
                                    obj.save()
                            elif "/" in cell_data:
                                for ip in IPNetwork(cell_data):
                                    try:
                                        obj = Ip.objects.get(ip=ip)
                                    except Ip.DoesNotExist:
                                        obj = Ip(collect_id=collect_id, ip=ip)
                                        obj.save()
                            elif "-" in cell_data:
                                pos = (cell_data.find("-"))
                                ip_s = cell_data[:pos]
                                ip_e = cell_data[pos+1:]
                                for ip in IPRange(ip_s, ip_e):
                                    try:
                                        obj = Ip.objects.get(ip=ip)
                                    except Ip.DoesNotExist:
                                        obj = Ip(collect_id=collect_id, ip=ip)
                                        obj.save()
                            else:
                                pass
            else:
                pass
        return super(CollectIpUpdate, self).form_valid(form)

class CollectDelete(DeleteView):
    model = Collect
    success_url = reverse_lazy('collects')
    template_name = 'collect/collect_confirm_delete.html'

class PortCreate(CreateView):
    model = Port
    fields = ['port']
    success_url = reverse_lazy('port-new')
    template_name = 'port/port_form.html'
    def get_context_data(self, **kwargs):
        context = super(PortCreate, self).get_context_data(**kwargs)
        context['ports'] = Port.objects.all()
        return context

class PortDelete(DeleteView):
    model = Port
    success_url = reverse_lazy('port-new')
    template_name = 'port/port_confirm_delete.html'

class ConfigureList(ListView):
    queryset = Configure.objects.all()
    template_name = 'configure/configures.html'
    context_object_name = 'Configures'

class ConfigureCreate(CreateView):
    model = Configure
    fields = ['scantime', 'email']
    success_url = reverse_lazy('configures')
    template_name = 'configure/configure_form.html'
    
    def form_valid(self, form):
        if form.is_valid():
            form.save()
            configure = Configure.objects.order_by('-id')[0]
            scan_ip(repeat=configure.scantime)
            return redirect(reverse_lazy('configures'))
            
class ConfigureUpdate(UpdateView):
    model = Configure
    success_url = 'configures'
    fields = ['scantime', 'email']
    template_name = 'configure/configure_form.html'

    def form_valid(self, form):
        if form.is_valid():
            form.save()
            configure = Configure.objects.order_by('-id')[0]
            scan_ip(repeat=configure.scantime)
            return redirect(reverse_lazy('configures'))
