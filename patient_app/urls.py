from django.urls import path, include
from django.urls import path
from .views import CommunicationCreateView, CommunicationReplyView
from .views import EHRListCreateView, EHRDetailView
from .views import AppointmentListCreateView, AppointmentDetailView

urlpatterns = [
    path('queries/', CommunicationCreateView.as_view(), name='create-query'),  # Endpoint for creating queries
    path('reply/<str:sender>/<str:receiver>/', CommunicationReplyView.as_view(), name='reply-query'),
    path('ehr/', EHRListCreateView.as_view(), name='ehr-list-create'),  # List and create EHRs
    path('ehr/<int:pk>/', EHRDetailView.as_view(), name='ehr-detail'),  # Retrieve, update, delete a specific EHR
    path('appointments/', AppointmentListCreateView.as_view(), name='appointment-list-create'),
    path('appointments/<int:pk>/', AppointmentDetailView.as_view(), name='appointment-detail'),
]
