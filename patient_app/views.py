from django.shortcuts import render
from rest_framework.permissions import BasePermission

# Create your views here.
class IsPatientUser(BasePermission):
    """
    Custom permission to allow only patient users to access the view.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'patient'
    
class IsAdminUser(BasePermission):
    """
    Custom permission to only allow admins to access this view.
    """
    def has_permission(self, request, view):
        return request.user.role == 'admin' 
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
  # A custom permission to ensure only patients can access this
from .serializers import CommunicationSerializer
from .models import Communication
from rest_framework import status


class CommunicationCreateView(APIView):
    permission_classes = [IsAuthenticated,IsPatientUser]
    
    def post(self, request):
        user = request.user  # The currently authenticated user
        
        # Determine sender and receiver based on the user's role
        if user.role == 'admin':  # If the user is an admin
            sender = 'admin'
            receiver = 'patient'
        elif user.role == 'patient':  # If the user is a patient
            sender = 'patient'
            receiver = 'admin'
        else:
            return Response({"detail": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Prepare the data with the sender and receiver dynamically set
        data = request.data.copy()
        data['sender'] = sender
        data['receiver'] = receiver
        
        # Now the 'sender' and 'receiver' are set automatically based on the user's role
        serializer = CommunicationSerializer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CommunicationReplyView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]  # Only admins can reply to queries
    
    """
    View for admin to reply to a query message from a patient.
    """
    def patch(self, request, sender, receiver):
        # Ensure the receiver is a patient and sender is admin
        if request.user.role != 'admin':
            return Response({"detail": "Only admins can reply."}, status=status.HTTP_400_BAD_REQUEST)

        communication = Communication.objects.filter(sender=sender, receiver=receiver, status='pending').first()

        if not communication:
            return Response({"detail": "No pending query found."}, status=status.HTTP_400_BAD_REQUEST)

        # Update the sent_message field with the admin's response and mark as resolved
        serializer = CommunicationSerializer(communication, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(status='resolved')  # Mark as resolved when admin replies
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import EHR
from .serializers import EHRSerializer
from rest_framework.generics import GenericAPIView
from .models import Appointment
from .serializers import AppointmentSerializer
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .models import EHR
from .serializers import EHRSerializer
from rest_framework import generics



class EHRListCreateView(ListCreateAPIView):
    permission_classes = [IsAuthenticated,IsPatientUser]

    """
    Handles listing all EHR records and creating a new one.
    """
    queryset = EHR.objects.all()
    serializer_class = EHRSerializer

class EHRDetailView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated,IsPatientUser]

    """
    Handles retrieving, updating, and deleting a specific EHR record by ID.
    """
    queryset = EHR.objects.all()
    serializer_class = EHRSerializer








# Appointment CRUD view using CreateReadUpdateDestroyAPIView
class AppointmentListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated,IsPatientUser]

    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer

# Appointment Retrieve, Update, and Delete view using CreateReadUpdateDestroyAPIView
class AppointmentDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated,IsPatientUser]

    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer