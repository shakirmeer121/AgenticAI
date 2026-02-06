from django.urls import path

from incidents.views import IncidentListView

urlpatterns = [
    path("", IncidentListView.as_view(), name="incident-list"),
]
