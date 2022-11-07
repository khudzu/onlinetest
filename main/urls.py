from django.urls import re_path

from . import views

app_name = 'main'

urlpatterns = [
    re_path(r'^create/$', views.create, name='create'),
    re_path(r'^data/$', views.data, name='data'),
    re_path(r'^login/$', views.login, name='login'),
    re_path(r'^logout/$', views.logout, name='logout'),
    re_path(r'^$', views.home, name='home'),
]
