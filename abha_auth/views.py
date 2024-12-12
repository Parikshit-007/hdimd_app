from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
import requests
from django.conf import settings

class InitiateAuthView(APIView):
    """
    Step 1: Initiates ABHA Login by sending an OTP to the user's mobile number linked with ABHA.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        abha_number = request.data.get('abha_number')
        if not abha_number:
            return Response({"error": "ABHA number is required"}, status=status.HTTP_400_BAD_REQUEST)

        url = f"{settings.ABDM_BASE_URL}/v1/auth/init"
        payload = {
            "id": abha_number,
            "purpose": "AUTH"
        }
        headers = {
            "Content-Type": "application/json",
            # Add client ID and secret if needed
            "X-Client-ID": settings.ABDM_CLIENT_ID,
            "X-Client-Secret": settings.ABDM_CLIENT_SECRET,
        }

        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 202:  # OTP sent successfully
                return Response({
                    "message": "OTP sent successfully",
                    "txnId": response.json().get("txnId")
                }, status=status.HTTP_200_OK)

            # Handle other errors from the API
            return Response({
                "error": f"API returned {response.status_code}",
                "details": response.json()
            }, status=response.status_code)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPView(APIView):
    """
    Step 2: Verifies OTP and returns an access token upon successful verification.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        txn_id = request.data.get('txnId')
        otp = request.data.get('otp')
        if not txn_id or not otp:
            return Response({"error": "Transaction ID and OTP are required"}, status=status.HTTP_400_BAD_REQUEST)

        url = f"{settings.ABDM_BASE_URL}/v1/auth/confirm"
        payload = {
            "txnId": txn_id,
            "otp": otp
        }
        headers = {
            "Content-Type": "application/json",
            # Add client ID and secret if needed
            "X-Client-ID": settings.ABDM_CLIENT_ID,
            "X-Client-Secret": settings.ABDM_CLIENT_SECRET,
        }

        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:  # OTP verification successful
                return Response({
                    "message": "Login successful",
                    "access_token": response.json().get("token")
                }, status=status.HTTP_200_OK)

            # Handle other errors from the API
            return Response({
                "error": f"API returned {response.status_code}",
                "details": response.json()
            }, status=response.status_code)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
