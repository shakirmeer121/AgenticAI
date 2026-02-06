"""Project URL configuration."""
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/logs/", include("logs.urls")),
    path("api/incidents/", include("incidents.urls")),
]
