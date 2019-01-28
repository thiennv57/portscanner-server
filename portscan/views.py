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

@background(schedule=1)
def scan_ip():
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
                            obj.scan_date = datetime.datetime.now()
                            obj.save()
                            print("Success updated")
                        except PortState.DoesNotExist:
                            obj = PortState(port_id=port.id, ip_id=ip.id, scan_date=datetime.datetime.now())
                            obj.save()
                            print("Success created")
                    else:
                        pass
                else:
                    pass

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
            elif end_ip:
                for ip in IPRange(ip_pool_start, ip_pool_end):
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
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
            else:
                for ip in IPRange(ip_pool_start, ip_pool_end):
                    try:
                        obj = Ip.objects.get(ip=ip)
                    except Ip.DoesNotExist:
                        obj = Ip(collect_id=collect_id, ip=ip)
                        obj.save()
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
            scan_ip(schedule=configure.scantime, repeat=2)
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
            scan_ip(schedule=configure.scantime, repeat=1)
            return redirect(reverse_lazy('configures'))

def result(request):
        return render(request, 'pages/result.html')