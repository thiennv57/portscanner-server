from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Collect, Ip, Port, Configure, PortState, CollectPort, IpPort
from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from .forms import CollectForm, IpForm, ConfigureForm
from django.urls import reverse_lazy
from django.db import transaction
from django.views.generic import CreateView, UpdateView, DeleteView, ListView, DetailView
from netaddr import *
from string import *
import nmap
from django.utils import timezone
import datetime
from background_task import background
import openpyxl
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template, render_to_string
from django.template import Context
from django.shortcuts import render,get_object_or_404 
from django.http import JsonResponse
from django.contrib import messages
from django.db.models import Q
import copy
import pdb

@background(schedule=1)
def scan_collect_ports(hosts, list_port_scan):
    print("Start time "+str(timezone.now()))
    try:
        nm = nmap.PortScanner()
        live_hosts = ""
        nm.scan(hosts=hosts,arguments='-sP')
        for host in nm.all_hosts():
            print('Host live: ', host)
            live_hosts = live_hosts + host + " "
        if not list_port_scan:
            nm.scan(live_hosts)
        else:
            nm.scan(live_hosts, ports=list_port_scan)
        protocols = nm[host].all_protocols()
        for host in nm.all_hosts():
            for protocol in protocols:
                ports = nm[host][protocol]
                open_ports = []
                for port in ports:
                    if ports[port]['state'] == 'open':
                        open_ports.append(port)
            create_portstate(host, open_ports)
            close_portstate(host, open_ports, list_port_scan)
        print("End time "+str(timezone.now()))
    except:
        pass
    return redirect(reverse_lazy("collects"))

def create_portstate(host, open_ports):
    ip=Ip.objects.get(ip=host)
    for port in open_ports:
        try:
            obj = PortState.objects.get(port=port, ip_id=ip.id)
            if obj.openning == False:
                obj.openning = True
                obj.save()
            else:
                pass
        except PortState.DoesNotExist:
            obj = PortState(port=port, ip_id=ip.id, scan_date=timezone.now(), last_scan_date=timezone.now(), openning=True)
            obj.save()

def close_portstate(host, open_ports, list_port_scan):
    ip=Ip.objects.get(ip=host)
    openned_ports = []
    closed_ports = []
    if not list_port_scan:
        for port in ip.portstate_set.all():
            openned_ports.append(port.port)
        closed_ports = [p for p in openned_ports if p not in open_ports]
    else:
        list_port_scan = list_port_scan.split(",")
        closed_ports = [int(p) for p in list_port_scan if int(p) not in open_ports]
    if closed_ports:
        for port in closed_ports:
            try:
                obj = PortState.objects.get(port=port, ip_id=ip.id)
                obj.openning = False
                obj.save()
            except:
                pass
    else:
        pass   


def send_email(scantime_present):
    merge_data = {
        'collects': Collect.objects.all,
        'scantime_present': scantime_present
    }
    plaintext_context = Context(autoescape=False)
    subject = 'Scan result report'
    text_body = 'Time: '+str(scantime_present)
    html_body = render_to_string("configure/email.html", merge_data)
    mail_to = Configure.objects.order_by('-id')[0].email
    msg = EmailMultiAlternatives(subject=subject, from_email=settings.EMAIL_HOST_USER, to=[mail_to], body=text_body)
    msg.attach_alternative(html_body, "text/html")
    msg.send()

def create_or_update_collect(collect):
    ip = collect.request.POST['start_ip']
    ip_subnet = collect.request.POST['start_ip_subnet']
    subnet = collect.request.POST['subnetmask']
    ip_pool_start = collect.request.POST['start_ip_pool']
    ip_pool_end = collect.request.POST['end_ip_pool']
    collect_id=collect.object.id
    if ip:
        ips = ip.split(",")
        hosts = ""
        for ip in ips:
            ip = ip.strip()
            try:
                obj = Ip.objects.get(ip=ip)
            except Ip.DoesNotExist:
                obj = Ip(collect_id=collect_id, ip=ip)
                obj.save()             
                hosts = hosts + (str(obj.ip)) + " "

        scan_collect_ports(hosts, "")
    elif ip_subnet:
        hosts = ""
        for ip in IPNetwork(ip_subnet+str('/')+str(subnet)):
            try:
                obj = Ip.objects.get(ip=ip)
            except Ip.DoesNotExist:
                obj = Ip(collect_id=collect_id, ip=ip)
                obj.save()
                hosts = hosts + (str(obj.ip)) + " "
        scan_collect_ports(hosts, "")
    elif ip_pool_start:
        hosts = ""
        for ip in IPRange(ip_pool_start, ip_pool_end):
            try:
                obj = Ip.objects.get(ip=ip)
            except Ip.DoesNotExist:
                obj = Ip(collect_id=collect_id, ip=ip)
                obj.save()
                hosts = hosts + (str(obj.ip)) + " "
        scan_collect_ports(hosts, "")
    elif collect.request.FILES:
        excel_file = collect.request.FILES["excel_file"]
        wb = openpyxl.load_workbook(excel_file)
        worksheet = wb["Sheet1"]
        hosts = ""
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
                            hosts = hosts + (str(obj.ip)) + " "
                    elif "/" in cell_data:
                        for ip in IPNetwork(cell_data):
                            try:
                                obj = Ip.objects.get(ip=ip)
                            except Ip.DoesNotExist:
                                obj = Ip(collect_id=collect_id, ip=ip)
                                obj.save()
                                hosts = hosts + (str(obj.ip)) + " "
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
                                hosts = hosts + (str(obj.ip)) + " "
                    else:
                        pass
        scan_collect_ports(hosts, "")
    else:
        pass

    if collect.request.POST['collect_port']:
        ports = collect.request.POST['collect_port'].split(",")
        for port in ports:
            port = port.strip()
            try:
                obj = CollectPort.objects.get(port=port)
            except CollectPort.DoesNotExist:
                obj = CollectPort(collect_id=collect_id, port=port)
                obj.save()
    else:
        pass

class CollectList(ListView):
    # queryset = Collect.objects.all().order_by("name")
    template_name = 'collect/collects.html'
    context_object_name = 'Collects'
    paginate_by = 10

    def get_queryset(self):
        try:
            search = self.request.GET.get('port')
        except KeyError:
            search = None
        if search:
            port_states = PortState.objects.filter(port=search)
            collect_list = []
            for port in port_states:
                collect = port.ip.collect
                collect_list.append(collect)
            for collect in collect_list:
                collect_list = Collect.objects.filter(Q(name__icontains=collect.name))
        else:
            collect_list = Collect.objects.all().order_by("name")
        return collect_list

class CollectCreate(CreateView):
    model = Collect
    fields = "__all__"

class CollectDetail(DetailView): 
    model = Collect
    template_name = 'collect/collect_detail.html'
    
class CollectUpdate(UpdateView):
    model = Collect
    success_url = '/'
    fields = "__all__"
    paginate_by = 12
    

class CollectIpCreate(CreateView):
    model = Collect
    fields = "__all__"
    success_url = reverse_lazy('collects')
    template_name = 'collect/collect_form.html'

    def form_valid(self, form):
        with transaction.atomic():
            self.object = form.save()
            create_or_update_collect(self)
            messages.success(self.request, 'Create group successfully. Please wait to scan all ports of ips!')
        return super(CollectIpCreate, self).form_valid(form)

class CollectIpUpdate(UpdateView):
    model = Collect
    fields = "__all__"
    # success_url = reverse_lazy('collects')
    template_name = 'collect/collect_form.html'
    
    def form_valid(self, form):
        with transaction.atomic():
            self.object = form.save()
            collect=self.object
            create_or_update_collect(self)
            list_port_scan = []
            ports = Port.objects.all()
            for port in ports:
                list_port_scan.append(port.port)
            collectport_list = copy.deepcopy(list_port_scan)
            for port in collect.collectport_set.all():
                if port.port not in collectport_list:
                    collectport_list.append(port.port)
            if "scan_all" in self.request.POST:
                hosts = ""
                for ip in collect.ip_set.all():
                    hosts = hosts + (str(ip.ip)) + " "
                scan_collect_ports(hosts, "")
                messages.success(self.request, 'Scanning all ports of all ips. Please check after several minutes !')
            elif ("scan_ports" in self.request.POST or collect.scanday or collect.scanhour):
                ip_has_ports = ""
                ip_no_ports = ""
                collect_scan_time = collect.scanday*60+collect.scanhour
                for ip in collect.ip_set.all():
                    ipport_list = copy.deepcopy(collectport_list)
                    if ip.ipport_set.all():
                        ip_has_ports.append(ip.ip)
                        for port in ip.ipport_set.all():
                            if port.port not in ipport_list:
                                ipport_list.append(port.port)
                    else:
                        ip_no_ports = ip_no_ports + str(ip.ip) + " "
                for ip in ip_has_ports:
                    scan_collect_ports(str(ip.ip), str(ipport_list).strip('[]'), repeat=collect_scan_time)
                scan_collect_ports(ip_no_ports, str(collectport_list).strip('[]'), repeat=collect_scan_time)
                messages.success(self.request, 'Scanning ports are configured of all ips. Please check after several minutes !')
            else:
                messages.success(self.request, 'Update group successfully!')
        return redirect(reverse_lazy("collect-update", kwargs={'pk': self.object.id}))

class CollectDelete(DeleteView):
    model = Collect
    success_url = reverse_lazy('collects')
    
class IpUpdate(UpdateView):
    model = Ip
    fields = ['ip', 'description']
    # success_url = reverse_lazy('ip-update', kwargs = {'pk' : self.object.id, })
    template_name = 'ip/ip_form.html'

    def form_valid(self, form):
        with transaction.atomic():
            self.object = form.save()
            ip = self.object
            if self.request.POST['ip_port']:
                ports = self.request.POST['ip_port'].split(",")
                for port in ports:
                    port = port.strip()
                    try:
                        obj = IpPort.objects.get(port=port)
                    except IpPort.DoesNotExist:
                        obj = IpPort(ip_id=self.object.id, port=port)
                        obj.save()
                messages.success(self.request, 'Add port successfully!')
            elif "scan_all" in self.request.POST:
                scan_collect_ports(str(ip.ip), "")
                messages.success(self.request, 'Scanning all ports of ip. Please check after several minutes !')
            elif "scan_ports" in self.request.POST:
                ipport_list = []
                for port in ip.ipport_set.all():
                    ipport_list.append(port.port)
                scan_collect_ports(str(ip.ip), str(ipport_list).strip('[]'))
                messages.success(self.request, 'Scanning ports are configured of ip. Please check after several minutes !')
            else:
                messages.success(self.request, 'Update Ip successfully!')        
        return redirect(reverse_lazy("ip-update", kwargs={'pk': self.object.id}))

class IpDetail(DetailView): 
    model = Ip
    template_name = 'ip/ip_detail.html'
    
class IpDelete(DeleteView):
    model = Ip
    success_url = reverse_lazy('collects')
    template_name = 'ip/ip_confirm_delete.html'

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
    queryset = Configure.objects.order_by('id')
    template_name = 'configure/configures.html'
    context_object_name = 'Configures'

class ConfigureCreate(CreateView):
    model = Configure
    fields = "__all__"
    success_url = reverse_lazy('configures')
    template_name = 'configure/configure_form.html'
            
class ConfigureUpdate(UpdateView):
    model = Configure
    fields = "__all__"
    success_url = reverse_lazy('configures')
    template_name = 'configure/configure_form.html'

class CollectPortDelete(DeleteView):
    model = CollectPort
    
    def get_success_url(self):
        messages.success(self.request, 'Delete port successfully')
        return reverse_lazy("collect-update", kwargs={'pk': self.object.collect.id})

class IpPortDelete(DeleteView):
    model = IpPort
    template_name = 'port/port_confirm_delete.html'
    def get_success_url(self):
        messages.success(self.request, 'Delete port successfully')
        return reverse_lazy("ip-update", kwargs={'pk': self.object.ip.id})