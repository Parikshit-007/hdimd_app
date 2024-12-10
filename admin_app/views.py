from django.shortcuts import render

# Create your views here.
from .serializers import AdminCreateUserSerializer, AdminLoginSerializer, AdminUserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers, status, views
from rest_framework.response import Response
from .models import Hospital, Doctor, Resource, Alert, Report, Communication, ProgramPerformance, AuditLog, IncidentReport
from .serializers import (
    HospitalSerializer, DoctorSerializer, ResourceSerializer, AlertSerializer,
    ReportSerializer, CommunicationSerializer, ProgramPerformanceSerializer,
    AuditLogSerializer, IncidentReportSerializer
)
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response

from .serializers import  PolicySerializer
#from admin_mobile.auth import AdminTokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny


from rest_framework.permissions import AllowAny

from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    """
    Custom permission to allow only admin users to access the view.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'


class AdminSignupAPIView(APIView):
    permission_classes= [AllowAny]
    """Handles admin signup."""
    permission_classes = [AllowAny]  # Allow anyone to access the signup endpoint

    def post(self, request):
        serializer = AdminCreateUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Saves the new user to the database
            return Response(
                {"message": "Admin registered successfully."}, 
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class DataSubmitChoiceSerializer(serializers.Serializer):
   # authentication_classes = [AdminTokenAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    data_type = serializers.ChoiceField(choices=[
        ('hospital', 'Hospital'),
        ('doctor', 'Doctor'),
        ('resource', 'Resource'),
        ('alert', 'Alert'),
        ('report', 'Report'),
        ('communication', 'Communication'),
        ('program_performance', 'Program Performance'),
        ('audit_log', 'Audit Log'),
        ('incident_report', 'Incident Report')
    ])

class SubmitDataView(views.APIView):
   # authentication_classes = [AdminTokenAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, *args, **kwargs):
        # First, let the user choose the data type
        data_type_serializer = DataSubmitChoiceSerializer(data=request.data)
        if data_type_serializer.is_valid():
            data_type = data_type_serializer.validated_data['data_type']
            if data_type == 'hospital':
                serializer = HospitalSerializer(data=request.data)
            elif data_type == 'doctor':
                serializer = DoctorSerializer(data=request.data)
            elif data_type == 'resource':
                serializer = ResourceSerializer(data=request.data)
            elif data_type == 'alert':
                serializer = AlertSerializer(data=request.data)
            elif data_type == 'report':
                serializer = ReportSerializer(data=request.data)
            elif data_type == 'communication':
                serializer = CommunicationSerializer(data=request.data)
            elif data_type == 'program_performance':
                serializer = ProgramPerformanceSerializer(data=request.data)
            elif data_type == 'audit_log':
                serializer = AuditLogSerializer(data=request.data)
            elif data_type == 'incident_report':
                serializer = IncidentReportSerializer(data=request.data)

            # Now validate and save the data for the selected model
            if serializer.is_valid():
                serializer.save()
                return Response({"message": f"{data_type.capitalize()} data submitted successfully."}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(data_type_serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class DisplayAllinfoView(APIView):
    #authentication_classes = [AdminTokenAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, *args, **kwargs):
        try:
            # Retrieve data for all hospitals and their related models
            hospital_data = Hospital.objects.all()  # Get all hospitals
            doctor_data = Doctor.objects.all()  # Get all doctors
            resource_data = Resource.objects.all()  # Get all resources
            alert_data = Alert.objects.all()  # Get all alerts
            report_data = Report.objects.all()  # Get all reports
            communication_data = Communication.objects.all()  # Get all communications
            program_performance_data = ProgramPerformance.objects.all()  # Get all program performance data
            audit_log_data = AuditLog.objects.all()  # Get all audit logs
            incident_report_data = IncidentReport.objects.all()  # Get all incident reports

            # Serialize the data
            hospital_serializer = HospitalSerializer(hospital_data, many=True)
            doctor_serializer = DoctorSerializer(doctor_data, many=True)
            resource_serializer = ResourceSerializer(resource_data, many=True)
            alert_serializer = AlertSerializer(alert_data, many=True)
            report_serializer = ReportSerializer(report_data, many=True)
            communication_serializer = CommunicationSerializer(communication_data, many=True)
            program_performance_serializer = ProgramPerformanceSerializer(program_performance_data, many=True)
            audit_log_serializer = AuditLogSerializer(audit_log_data, many=True)
            incident_report_serializer = IncidentReportSerializer(incident_report_data, many=True)

            # Combine all serialized data
            combined_data = {
                "hospital_data": hospital_serializer.data,
                "doctor_data": doctor_serializer.data,
                "resource_data": resource_serializer.data,
                "alert_data": alert_serializer.data,
                "report_data": report_serializer.data,
                "communication_data": communication_serializer.data,
                "program_performance_data": program_performance_serializer.data,
                "audit_log_data": audit_log_serializer.data,
                "incident_report_data": incident_report_serializer.data
            }

            return Response(combined_data, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle any potential errors
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# class PolicyCategoryViewSet(viewsets.ModelViewSet):
#     queryset = PolicyCategory.objects.all()
#     serializer_class = PolicyCategorySerializer
#     permission_classes = [IsAuthenticated]
from rest_framework.parsers import MultiPartParser, FormParser

class SubmitPolicyView(views.APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    parser_classes = (MultiPartParser, FormParser)
    def post(self, request, *args, **kwargs):
        # Parse the incoming JSON data
        serializer = PolicySerializer(data=request.data)

        # Validate and save the policy if data is correct
        if serializer.is_valid():
            policy = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Return errors if validation fails
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
# class AmbulanceView(views.APIView):
#     def post(self, request, *args, **kwargs):
#         # Parse the incoming JSON data
#         serializer = AmbulanceSerailizer(data=request.data)

#         # Validate and save the policy if data is correct
#         if serializer.is_valid():
#             ambulance = serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
        
#         # Return errors if validation fails
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
  
  
  
  
    
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import Ambulance
# from .serializers import AmbulanceSerializer

# class UpdateAmbulanceLocation(APIView):
#     def post(self, request):
#         serializer = AmbulanceSerializer(data=request.data)
#         if serializer.is_valid():
#             ambulance, created = Ambulance.objects.update_or_create(
#                 identifier=serializer.validated_data['identifier'],
#                 defaults={
#                     'latitude': serializer.validated_data['latitude'],
#                     'longitude': serializer.validated_data['longitude']
#                 }
#             )
#             return Response({"message": "Location updated successfully!"}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    





# # communications
# from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
# from django.shortcuts import get_object_or_404
# # List all communications or create a new communication
# class CommunicationListCreateView(APIView):
#     def get(self, request):
#         communications = Communication.objects.all()
#         serializer = CommunicationSerializer(communications, many=True)
#         return Response(serializer.data)

#     def post(self, request):
#         serializer = CommunicationSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# # Retrieve, update or delete a specific communication
# class CommunicationDetailView(RetrieveUpdateDestroyAPIView):
#     def get(self, request, pk):
#         communication = get_object_or_404(Communication, pk=pk)
#         serializer = CommunicationSerializer(communication)
#         return Response(serializer.data)

#     def put(self, request, pk):
#         communication = get_object_or_404(Communication, pk=pk)
#         serializer = CommunicationSerializer(communication, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def patch(self, request, pk):
#         communication = get_object_or_404(Communication, pk=pk)
#         serializer = CommunicationSerializer(communication, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def delete(self, request, pk):
#         communication = get_object_or_404(Communication, pk=pk)
#         communication.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)










# policy 
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from .models import Policy
from .serializers import PolicySerializer
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView

# View for creating and listing policies
class PolicyListCreateView(ListCreateAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    queryset = Policy.objects.all()
    serializer_class = PolicySerializer

    def post(self, request, *args, **kwargs):
        """
        Create a new policy.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# View for retrieving, updating, and deleting a policy
class PolicyDetailView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    queryset = Policy.objects.all()
    serializer_class = PolicySerializer

    def get(self, request, pk, *args, **kwargs):
        """
        Retrieve a specific policy by its ID.
        """
        return super().get(request, *args, **kwargs)

    def put(self, request, pk, *args, **kwargs):
        """
        Fully update a policy.
        """
        return super().put(request, *args, **kwargs)

    def patch(self, request, pk, *args, **kwargs):
        """
        Partially update a policy.
        """
        return super().patch(request, *args, **kwargs)

    def delete(self, request, pk, *args, **kwargs):
        """
        Delete a policy.
        """
        return super().delete(request, *args, **kwargs)










# communication
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Communication
from .serializers import CommunicationSerializer
class IsPatientUser(BasePermission):
    """
    Custom permission to allow only patient users to access the view.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'patient'
class CommunicationCreateView(APIView):
    permission_classes = [IsAuthenticated, IsPatientUser]  # Only patients can create a query
    
    """
    View for creating a new communication (query from patient to admin).
    """
    def post(self, request):
        # Ensure that the communication is between a patient and an admin
        if request.user.role != 'patient':
            return Response({"detail": "Only patients can create queries."}, status=status.HTTP_400_BAD_REQUEST)

        # The sender (patient) and receiver (admin) are passed in the data
        data = request.data
        data['sender'] = request.user.email  # Set the sender as the logged-in patient
        data['receiver'] = 'admin'  # The receiver is always admin for patient queries
        
        serializer = CommunicationSerializer(data=data)
        if serializer.is_valid():
            serializer.save()  # Save the communication query
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




class CommunicationUnsendView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    """
    View for admin to unsend (delete) a message.
    """
    def patch(self, request, sender, receiver):
        communication = Communication.objects.filter(sender=sender, receiver=receiver).first()
        
        if not communication:
            return Response({"detail": "Message not found."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure only admins can unsend their own messages
        if communication.receiver != "Admin":
            return Response({"detail": "Only admins can unsend messages sent by them."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark the message as unsent
        communication.deleted_by_admin = True
        communication.status = 'unsent'
        communication.save()

        return Response({"detail": "Message has been unsent."}, status=status.HTTP_200_OK)









# Dcotor Views
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .models import Doctor
from .serializers import DoctorSerializer

# Create & List all Doctors
class DoctorListCreateView(ListCreateAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    queryset = Doctor.objects.all()
    serializer_class = DoctorSerializer

    def post(self, request, *args, **kwargs):
        # Custom behavior for creating a doctor if needed
        return super().post(request, *args, **kwargs)

# Retrieve, Update, and Delete a specific Doctor by ID
class DoctorRetrieveUpdateDestroyView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    queryset = Doctor.objects.all()
    serializer_class = DoctorSerializer
    lookup_field = 'id'  # Using 'id' as the lookup field
