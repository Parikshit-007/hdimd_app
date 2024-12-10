from rest_framework import serializers
from .models import Communication

class CommunicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Communication
        fields = ['id', 'sender', 'receiver', 'message', 'status', 'created_at', 'updated_at', 'deleted_by_admin']
