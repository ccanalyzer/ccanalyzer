from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^audit$', views.audit, name='audit'),
    url(r'^search', views.search, name='search'),
    url(r'^download$', views.download, name='download'),
    url(r'^audit_upload$', views.audit_upload, name='audit_upload'),
]
