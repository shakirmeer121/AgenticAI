from rest_framework import generics

from incidents.models import Incident
from incidents.serializers import IncidentSerializer


class IncidentListView(generics.ListAPIView):
    queryset = Incident.objects.all().order_by("-created_at")
    serializer_class = IncidentSerializer
