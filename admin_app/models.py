from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ValidationError
# Encryption key
SECRET_KEY = b'603zgLcePQ9gH7Ja7y4IvuyTKbLNEgC3KqHv4IVFNlw='
cipher_suite = Fernet(SECRET_KEY)

class AdminUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required.")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.is_active = True
        user.set_password(password)  # Encrypt and store the password
        user.save()
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if not extra_fields.get('is_staff'):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get('is_superuser'):
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, username, password, **extra_fields)


class AdminUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    encrypted_password = models.BinaryField()  # Store the encrypted password
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    last_login = models.DateTimeField(auto_now=True, null=True)

    # Custom related_name to avoid clashes with auth.User
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='admin_users',  # Avoid conflict by renaming reverse accessor
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='admin_users',  # Avoid conflict by renaming reverse accessor
        blank=True
    )

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = AdminUserManager()

    def set_password(self, password):
        """Encrypt and securely store the password."""
        self.encrypted_password = cipher_suite.encrypt(password.encode())

    def check_password(self, password):
        """Decrypt and validate the password."""
        try:
            decrypted_password = cipher_suite.decrypt(self.encrypted_password).decode()
            return password == decrypted_password
        except InvalidToken:
            return False

    def has_module_perms(self, app_label):
        """Grant module-level permissions."""
        return True

    def has_perm(self, perm, obj=None):
        """Grant specific object-level permissions."""
        return True

    def __str__(self):
        """Readable representation."""
        return self.username




class Hospital(models.Model):
    name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    total_beds = models.IntegerField()
    available_beds = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name







class Resource(models.Model):
    RESOURCE_TYPES = [
        ('equipment', 'Equipment'),
        ('medicine', 'Medicine'),
    ]
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=50, choices=RESOURCE_TYPES)
    quantity = models.IntegerField()
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='resources')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.type})"


class Alert(models.Model):
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='alerts')
    message = models.TextField()
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Alert for {self.hospital.name}"


class Report(models.Model):
    REPORT_TYPES = [
        ('incident', 'Incident'),
        ('performance', 'Performance'),
    ]
    title = models.CharField(max_length=255)
    type = models.CharField(max_length=50, choices=REPORT_TYPES)
    content = models.TextField()
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"{self.title} - {self.type}"





class ProgramPerformance(models.Model):
    program_name = models.CharField(max_length=255)
    statistics = models.JSONField()
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='program_performance')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.program_name


class AuditLog(models.Model):
    user = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True)
    action = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username if self.user else 'System'}: {self.action}"


class IncidentReport(models.Model):
    title = models.CharField(max_length=255)
    details = models.TextField()
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='incident_reports')
    is_resolved = models.BooleanField(default=False)
    reported_by = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Incident: {self.title}"
    
    


    
    
    
    
#Policies 
class Policy(models.Model):
    TARGET_CHOICES = [
        ('hospital', 'Hospital'),
        ('user', 'User'),
        ('both', 'Both Hospital and User')
    ]

    IMPLEMENTATION_SCOPE_CHOICES = [
        ('state', 'State'),
        ('city', 'City'),
        ('region', 'Region'),
        ('national', 'National')
    ]

    CATEGORY_CHOICES = [
        ('infrastructure', 'Infrastructure and Resource Enhancement'),
        ('quality', 'Quality Assurance and Performance'),
        ('workforce', 'Workforce Policies'),
        ('accessibility', 'Accessibility and Affordability'),
        ('awareness', 'Health Awareness and Promotion'),
        ('public_health', 'Public Health and Safety'),
        ('financial', 'Financial and Incentive-Based Policies'),
        ('research', 'Research and Innovation')
    ]
    scheme_logo = models.FileField(upload_to='policy_logos/', null=False, blank=False, default='policy_logos/default_scheme.jpg')
    name = models.CharField(max_length=255, unique=True)
    start_age = models.PositiveIntegerField(null=True, blank=True)
    end_age = models.PositiveIntegerField(null=True, blank=True)
    description = models.TextField()
    target_audience = models.CharField(max_length=20, choices=TARGET_CHOICES)
    implementation_scope = models.CharField(max_length=20, choices=IMPLEMENTATION_SCOPE_CHOICES)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    budget_allocated = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    # created_by = models.ForeignKey(
    #     settings.AUTH_USER_MODEL,
    #     on_delete=models.SET_NULL,
    #     null=True,
    #     related_name='created_policies'
    # )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    external_links=models.CharField(blank=True, max_length=100)
    def clean(self):
        # Validate that start_age is less than or equal to end_age if both are provided
        if self.start_age is not None and self.end_age is not None:
            if self.start_age > self.end_age:
                raise ValidationError("Start age cannot be greater than end age.")
    def __str__(self):
        return f"{self.name} ({self.get_target_audience_display()})"







# ambulance (adding and updating if an ambulance is available for booking or not)


# class Ambulance(models.Model):
#     TYPE_CHOICES = [
#         ('small', 'Small/Compact Ambulance'),
#         ('medium', 'Medium-Sized Ambulance'),
#         ('large', 'Large/Heavy-Duty Ambulance'),
#     ]

#     STATUS_CHOICES = [
#         ('available', 'Available for Booking'),
#         ('unavailable', 'Not Available for Booking'),
#         ('in_service', 'In Service'),
#     ]

#     ambulance_id = models.CharField(max_length=50, unique=True, help_text="Unique ID for the ambulance")
#     type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='medium', help_text="Type of the ambulance based on size")
#     driver_name = models.CharField(max_length=100, help_text="Name of the driver assigned to the ambulance")
#     driver_contact = models.CharField(max_length=15, help_text="Contact number of the driver")
#     identifier = models.CharField(max_length=100, unique=True)
#     latitude = models.FloatField()
#     longitude = models.FloatField()
#     last_updated = models.DateTimeField(auto_now=True)
#     status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='available', help_text="Booking status of the ambulance")
#     added_on = models.DateTimeField(auto_now_add=True, help_text="Date and time when the ambulance was added")
#     last_updated = models.DateTimeField(auto_now=True, help_text="Last updated time for ambulance details")
#     is_active = models.BooleanField(default=True, help_text="Whether the ambulance is actively operating")

#     def __str__(self):
#         return f"Ambulance {self.ambulance_id} ({self.get_type_display()}) - {self.get_status_display()}"









# Queries incoming and status check 
from django.contrib.auth.models import User 

class Communication(models.Model):
    ROLE_CHOICES = [
        ('User', 'User'),
        ('Admin', 'Admin'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('resolved', 'Resolved'),
        ('unsent', 'Unsent'),  # For unsent messages
    ]

    sender = models.CharField(max_length=100, help_text="The sender of the message (User or Admin)")
    receiver = models.CharField(max_length=100, help_text="The receiver of the message (User or Admin)")
    title = models.CharField(max_length=255, help_text="Title of the message or query")
    message = models.TextField(help_text="The content of the message or query")
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='User',
        help_text="Role of the sender"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        help_text="Current status of the query"
    )
    sent_message = models.CharField(
        max_length=50,
        blank=True,
        help_text="Optional message sent in response"
    )
    timestamp = models.DateTimeField(auto_now_add=True, help_text="Time when the message was sent")
    deleted_by_admin = models.BooleanField(default=False, help_text="Flag to indicate if the message has been unsent by the admin")

    def __str__(self):
        return f"Message from {self.sender} to {self.receiver} - {self.title}"

    class Meta:
        verbose_name = "Communication"
        verbose_name_plural = "Communications"
        ordering = ['-timestamp']  # Orders by most recent messages first






# hospitals
class Doctor(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    
    name = models.CharField(max_length=255)
    specialization = models.CharField(max_length=255)
    
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='doctors')
    
    # Contact details
    contact_number = models.CharField(max_length=15, help_text="Doctor's contact number")
    email = models.EmailField(max_length=255, unique=True, help_text="Doctor's email address")
    
    # Address details
    address = models.TextField(help_text="Doctor's full address")
    
    # Gender and profile photo
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, help_text="Doctor's gender")
    profile_photo = models.ImageField(upload_to='doctor_photos/', blank=True, null=True, help_text="Profile photo of the doctor")
    
    # Medical License and experience details
    medical_license_number = models.CharField(max_length=100, unique=True, help_text="Doctor's medical license number")
    license_file = models.FileField(upload_to='doctor_licenses/', blank=True, null=True, help_text="File containing the doctor's medical license")
    
    years_of_experience = models.IntegerField(default=0, help_text="Number of years of experience")
    
    # Availability and status
    is_available = models.BooleanField(default=True, help_text="Whether the doctor is available for consultations")
    status = models.CharField(
        max_length=20,
        choices=[('active', 'Active'), ('inactive', 'Inactive'), ('on_leave', 'On Leave')],
        default='active',
        help_text="Current status of the doctor"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.specialization}"

    class Meta:
        verbose_name = "Doctor"
        verbose_name_plural = "Doctors"
        ordering = ['name']