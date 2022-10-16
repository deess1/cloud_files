from django.conf.urls import patterns, include, url

from cloud_files.cloud_files import cf_api
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = patterns('',
                       # cloud files API
                       url(r'^cloud_files/(\w+)$', cf_api),
)

