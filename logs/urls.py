from django.urls import path

from logs.views import LogIngestView
from .views import home

urlpatterns = [
    path("", LogIngestView.as_view(), name="log-ingest"),
    path("home/", home, name="home"),
]

