from django.db import models


class Log(models.Model):
    source = models.CharField(max_length=255, default="unknown")
    timestamp = models.DateTimeField()
    raw_message = models.TextField()
    normalized = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.source} @ {self.timestamp.isoformat()}"
