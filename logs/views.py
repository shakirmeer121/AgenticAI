from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.orchestrator import AgentOrchestrator
from logs.serializers import LogIngestSerializer



class LogIngestView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = LogIngestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        logs = serializer.validated_data["logs"]
        orchestrator = AgentOrchestrator()
        result = orchestrator.run(logs)
        return Response(result, status=status.HTTP_201_CREATED)

from django.shortcuts import render

def home(request):
    return render(request, "logs/home.html")
