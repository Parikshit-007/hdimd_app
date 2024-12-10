from django.db import models

# Create your models here.
from django.db import models

class Communication(models.Model):
    sender = models.CharField(max_length=100)  # Email of the sender (either patient or admin)
    receiver = models.CharField(max_length=100)  # The receiver (either 'admin' or 'patient')
    message = models.TextField()  # The communication message
    status = models.CharField(max_length=10, default='pending')  # Status of the communication ('pending', 'resolved')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_by_admin = models.BooleanField(default=False)  # To mark if an admin has unsent the message

    def __str__(self):
        return f"Message from {self.sender} to {self.receiver}"
from django.db import models
from cryptography.fernet import Fernet
import base64
import os
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# Key generation for encryption (Store this securely for decryption)
key = base64.urlsafe_b64encode(os.urandom(32))

def encrypt_data(data):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data):
    fernet = Fernet(key)
    return fernet.decrypt(data.encode()).decode()

class EHR(models.Model):
    UPLOAD_TYPES = (
        ('text', 'Text'),
        ('file', 'File'),
    )
    upload_type = models.CharField(max_length=10, choices=UPLOAD_TYPES)
    title = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    file = models.FileField(upload_to='uploads/', blank=True, null=True)
    encrypted_data = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Validation before saving
        if self.upload_type == 'text':
            if not self.description:
                raise ValueError("Description is required for text upload type.")
            self.encrypted_data = encrypt_data(self.description)
            self.description = None  # Clear plain text
            self.file = None  # Ensure file is cleared
        elif self.upload_type == 'file':
            if not self.file:
                raise ValueError("File is required for file upload type.")
            self.title = None  # Clear text-specific fields
            self.description = None
        else:
            raise ValueError("Invalid upload type.")

        super().save(*args, **kwargs)

    def get_decrypted_data(self):
        if self.encrypted_data:
            return decrypt_data(self.encrypted_data)
        return None


from django.db import models


# Appointment model linking Doctor and Patient using CharField
class Appointment(models.Model):
    doctor_name = models.CharField(max_length=255)
    patient_name = models.CharField(max_length=255)
    appointment_date = models.DateField()
    time_slot = models.DateTimeField()
    status = models.CharField(max_length=10, choices=(('pending', 'pending'), ('confirmed', 'confirmed')))
    total_visits = models.IntegerField()

    def __str__(self):
        return f"Appointment with Dr. {self.doctor_name} for {self.patient_name}"
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
