from django.shortcuts import render
from rest_framework.permissions import BasePermission, AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import get_user_model
from knox.models import AuthToken
from .serializers import UserSignupSerializer

User = get_user_model()


class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            role = serializer.validated_data.get('role')
            # Validate role
            if role not in ['admin', 'hospital', 'patient']:
                return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)

            # Save user with hashed password
            serializer.save(password=make_password(serializer.validated_data['password']))
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            # Retrieve user based on email
            user = User.objects.get(email=email)

            # Check if the password is valid
            if check_password(password, user.password):
                # Create a Knox token
                _, token = AuthToken.objects.create(user)

                return Response({
                    "message": "Login successful",
                    "user": {
                        "email": user.email,
                        "role": user.role,
                    },
                    "token": token
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'


class IsHospitalUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'hospital'


class IsPatientUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'patient'
