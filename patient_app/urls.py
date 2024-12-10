from django.urls import path, include
from django.urls import path
from .views import CommunicationCreateView, CommunicationReplyView

urlpatterns = [
    path('queries/', CommunicationCreateView.as_view(), name='create-query'),  # Endpoint for creating queries
    path('reply/<str:sender>/<str:receiver>/', CommunicationReplyView.as_view(), name='reply-query'),
]
