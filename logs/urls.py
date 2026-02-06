from django.urls import path

from logs.views import LogIngestView

urlpatterns = [
    path("", LogIngestView.as_view(), name="log-ingest"),
]
