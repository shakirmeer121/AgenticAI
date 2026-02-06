from django.db import models


class Incident(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    alert = models.BooleanField(default=False)
    confidence = models.FloatField(default=0.0)
    reason = models.TextField()
    attack_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=50)
    summary = models.TextField()
    recommendations = models.JSONField(default=dict)
    signals = models.JSONField(default=dict)

    def __str__(self) -> str:
        return f"Incident {self.id}: {self.attack_type} ({self.severity})"
