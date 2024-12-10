from rest_framework import serializers
from .models import Communication

class CommunicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Communication
        fields = ['id', 'sender', 'receiver', 'message', 'status', 'created_at', 'updated_at', 'deleted_by_admin']

from rest_framework import serializers
from .models import EHR

class EHRSerializer(serializers.ModelSerializer):
    decrypted_data = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = EHR
        fields = ['id', 'upload_type', 'title', 'description', 'file', 'encrypted_data', 'decrypted_data', 'created_at']
        read_only_fields = ['encrypted_data', 'decrypted_data', 'created_at']

    def validate(self, attrs):
        upload_type = attrs.get('upload_type')

        if upload_type == 'text':
            if not attrs.get('description'):
                raise serializers.ValidationError("Description is required for text upload type.")
            attrs['file'] = None  # Clear the file if provided
        elif upload_type == 'file':
            if not attrs.get('file'):
                raise serializers.ValidationError("File is required for file upload type.")
            attrs['title'] = None  # Clear text-specific fields
            attrs['description'] = None
        else:
            raise serializers.ValidationError("Invalid upload type.")

        return attrs

    def get_decrypted_data(self, obj):
        return obj.get_decrypted_data()





# appouintment
from .models import Appointment

class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = '__all__'
