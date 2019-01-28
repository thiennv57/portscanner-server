from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('result', views.result),
    path('groups', views.groups),
    path('configure', views.configure),
    path('group/<int:id>', views.group)
]