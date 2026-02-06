from rest_framework import serializers

from incidents.models import Incident


class IncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Incident
        fields = [
            "id",
            "created_at",
            "alert",
            "confidence",
            "reason",
            "attack_type",
            "severity",
            "summary",
            "recommendations",
            "signals",
        ]
