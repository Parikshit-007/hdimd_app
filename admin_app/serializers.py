from rest_framework import serializers
from .models import (
    AdminUser, Hospital, Doctor, Resource, Alert,
    Report, Communication, ProgramPerformance, AuditLog, IncidentReport, Policy 
    
)

from rest_framework import serializers
from .models import AdminUser

class AdminUserSerializer(serializers.ModelSerializer):
    """
    Serializer for basic AdminUser details.
    """
    class Meta:
        model = AdminUser
        fields = ['id', 'username', 'email']


class AdminCreateUserSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new AdminUser.
    """
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = AdminUser
        fields = ['email', 'username', 'password', 'password2']

    def validate(self, attrs):
        """
        Ensure the passwords match.
        """
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        """
        Create a new AdminUser.
        """
        user = AdminUser(
            email=validated_data['email'],
            username=validated_data['username']
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user


class AdminLoginSerializer(serializers.Serializer):
    """
    Serializer for AdminUser login.
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})

    def validate(self, attrs):
        """
        Validate username and password for login.
        """
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = AdminUser.objects.filter(username=username).first()
            if user and user.check_password(password):
                return user  # Return the authenticated user
            raise serializers.ValidationError("Invalid username or password.")
        raise serializers.ValidationError("Both username and password are required.")



class HospitalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hospital
        fields = '__all__'


# class DoctorSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Doctor
#         fields = '__all__'


class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = '__all__'





class ProgramPerformanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProgramPerformance
        fields = '__all__'


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = '__all__'


class IncidentReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = IncidentReport
        fields = '__all__'





# policies serializers
from rest_framework import serializers
from .models import Policy

class PolicySerializer(serializers.ModelSerializer):
    # Display the category choice as a readable label in the output
    category_display = serializers.SerializerMethodField()
    scheme_logo = serializers.FileField(required=False)

    class Meta:
        model = Policy
        fields = '__all__'  # Include all model fields
        read_only_fields = ['created_at', 'updated_at']  # These fields will be handled automatically

    def validate(self, data):
        # Additional validation for start_age and end_age
        start_age = data.get('start_age')
        end_age = data.get('end_age')
        if start_age is not None and end_age is not None and start_age > end_age:
            raise serializers.ValidationError("Start age cannot be greater than end age.")
        
        # Check if scheme_logo is provided
        if 'scheme_logo' not in data or not data['scheme_logo']:
            raise serializers.ValidationError("Scheme logo is required.")
        
        return data

    def get_category_display(self, obj):
        return obj.get_category_display()  # Provides the human-readable label for the category

    def create(self, validated_data):
        # Ensure 'created_by' is not included when creating a new policy, as it's not part of the model now
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Custom update logic if needed
        return super().update(instance, validated_data)







# ambulance
# class AmbulanceSerializer(serializers.ModelSerializer):
#     class Meta:
#         model= Ambulance
#         fields='__all__'
        
        

  
        
        
        
        
        
        
# communication
from rest_framework import serializers
from .models import Communication

from rest_framework import serializers
from .models import Communication

class CommunicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Communication
        fields = ['id', 'sender', 'receiver', 'message', 'status', 'created_at', 'updated_at', 'deleted_by_admin']






# doctor with crud
class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']