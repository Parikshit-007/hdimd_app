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
