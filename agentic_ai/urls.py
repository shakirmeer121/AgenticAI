"""Project URL configuration."""
from django.contrib import admin
from django.urls import include, path

import logs.views as views
from django.shortcuts import redirect
def root_redirect(request):
    return redirect("home/")

urlpatterns = [
    path("", root_redirect),
    path("", include("logs.urls")),
    path("admin/", admin.site.urls),
    path("api/logs/", include("logs.urls")),
    path("api/incidents/", include("incidents.urls")),
]
