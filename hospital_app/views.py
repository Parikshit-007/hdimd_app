from django.shortcuts import render
from rest_framework.permissions import BasePermission

# Create your views here.
class IsHospitalUser(BasePermission):
    """
    Custom permission to allow only hospital users to access the view.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'hospital'
