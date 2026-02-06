from rest_framework import serializers


class LogEntrySerializer(serializers.Serializer):
    source = serializers.CharField(required=False, allow_blank=True)
    timestamp = serializers.DateTimeField()
    message = serializers.CharField()
    metadata = serializers.DictField(required=False)


class LogIngestSerializer(serializers.Serializer):
    logs = LogEntrySerializer(many=True)
