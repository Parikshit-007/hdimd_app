from django.shortcuts import render

# Create your views here.
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

# Set your ABDM Sandbox Base URL
ABDM_BASE_URL = "https://sandbox.abdm.gov.in/gateway"

class InitiateAuthView(APIView):
    """
    Initiates ABHA Login by sending an OTP to the user's mobile.
    """
    def post(self, request):
        abha_number = request.data.get('abha_number')
        if not abha_number:
            return Response({"error": "ABHA number is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Call ABDM API to initiate authentication
            url = f"{ABDM_BASE_URL}/v1/auth/init"
            payload = {"id": abha_number, "purpose": "AUTH"}
            headers = {"Content-Type": "application/json"}
            
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 202:
                return Response({"message": "OTP sent successfully", "txnId": response.json().get("txnId")}, status=status.HTTP_200_OK)
            return Response(response.json(), status=response.status_code)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPView(APIView):
    """
    Verifies the OTP sent to the user's mobile and returns an access token.
    """
    def post(self, request):
        txn_id = request.data.get('txnId')
        otp = request.data.get('otp')
        if not txn_id or not otp:
            return Response({"error": "Transaction ID and OTP are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Call ABDM API to verify OTP
            url = f"{ABDM_BASE_URL}/v1/auth/confirm"
            payload = {"txnId": txn_id, "otp": otp}
            headers = {"Content-Type": "application/json"}
            
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                access_token = response.json().get("token")
                return Response({"message": "Login successful", "access_token": access_token}, status=status.HTTP_200_OK)
            return Response(response.json(), status=response.status_code)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)