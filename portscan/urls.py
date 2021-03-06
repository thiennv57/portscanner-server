from django.urls import path
from django.conf.urls import url

from . import views

urlpatterns = [
    path('', views.CollectList.as_view(), name="collects"),
    path('collects', views.CollectList.as_view(), name="collects"),
    path('collect/new', views.CollectIpCreate.as_view(), name="collect-new"),
    path('collect/<int:pk>/', views.CollectDetail.as_view(), name="collect-detail"),
    path('collect/<int:pk>/update', views.CollectIpUpdate.as_view(), name="collect-update"),
    path('collect/<int:pk>/delete', views.CollectDelete.as_view(), name='collect-delete'),
    path('ip/<int:pk>', views.IpDetail.as_view(), name="ip-detail"),
    path('ip/<int:pk>/update', views.IpUpdate.as_view(), name="ip-update"),
    path('ip/<int:pk>/delete', views.IpDelete.as_view(), name='ip-delete'),
    path('configures', views.ConfigureList.as_view(), name="configures"),
    path('configure/new', views.ConfigureCreate.as_view(), name="configure-new"),
    path('configure/<int:pk>/update', views.ConfigureUpdate.as_view(), name="configure-update"),
    path('port', views.PortCreate.as_view(), name="port-new"),
    path('port/<int:pk>/delete', views.PortDelete.as_view(), name='port-delete'),
    path('collectport/<int:pk>/delete', views.CollectPortDelete.as_view(), name='collectport-delete'),
    path('ipport/<int:pk>/delete', views.IpPortDelete.as_view(), name='ipport-delete'),
]