from django.urls import re_path

from . import views

app_name = 'main'

urlpatterns = [
    re_path(r'^create/$', views.create, name='create'),
    re_path(r'^data/$', views.data, name='data'),
    re_path(r'^benchmark/$', views.benchmark, name='benchmark'),
    re_path(r'^benchmark/image-encryption/$', views.image_benchmark, name='image_benchmark'),
    re_path(r'^ukur-latensi/$', views.benchmark, name='ukur_latensi'),
    re_path(r'^encrypted-images/(?P<filename>[^/]+)$', views.encrypted_image, name='encrypted_image'),
    re_path(r'^decrypted-images/(?P<filename>[^/]+)$', views.decrypted_image, name='decrypted_image'),
    re_path(r'^login/$', views.login, name='login'),
    re_path(r'^logout/$', views.logout, name='logout'),
    re_path(r'^$', views.home, name='home'),
]
