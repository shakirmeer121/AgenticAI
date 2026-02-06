from django.contrib import admin

from incidents.models import Incident


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("id", "attack_type", "severity", "confidence", "created_at")
    list_filter = ("severity", "attack_type")
    search_fields = ("summary", "reason")
