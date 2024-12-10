from django.urls import path
from .views import AdminSignupAPIView,  DisplayAllinfoView , SubmitPolicyView , PolicyListCreateView, PolicyDetailView , CommunicationCreateView , CommunicationReplyView , CommunicationUnsendView , DoctorListCreateView , DoctorRetrieveUpdateDestroyView
from .views import SubmitDataView
from django.conf import settings
from django.conf.urls.static import static
from django import views
urlpatterns = [
    path('signup/', AdminSignupAPIView.as_view(), name='admin-signup'),
    #path('login/', AdminLoginAPIView.as_view(), name='admin-login'),
    path('submit-data/', SubmitDataView.as_view(), name='submit_data'),
    path('hospital/all-data/', DisplayAllinfoView.as_view(), name='display-all-info'),
    
    
    
    path('submit-policy/', SubmitPolicyView.as_view(), name='submit_policy'),
    path('policies/', PolicyListCreateView.as_view(), name='policy-list-create'),
    path('policies/<int:pk>/', PolicyDetailView.as_view(), name='policy-detail'),
    
    
    # path('ambulance/',AmbulanceView.as_view(),name='admin-ambulance'),
    
    
    # path('communications/', CommunicationListCreateView.as_view(), name='communication-list-create'),
    # path('communications/<int:pk>/',CommunicationDetailView.as_view(), name='communication-detail'),
    
    
    
  
    # Comunications
    path('communication/create/', CommunicationCreateView.as_view(), name='create-query'),
    path('communication/reply/<str:sender>/<str:receiver>/', CommunicationReplyView.as_view(), name='reply-query'),
    path('communication/unsend/<str:sender>/<str:receiver>/', CommunicationUnsendView.as_view(), name='unsend-query'),
    
    
    # Dcotor 
    path('doctors/', DoctorListCreateView.as_view(), name='doctor-list-create'),
    
    # URL for retrieving, updating, or deleting a specific doctor
    path('doctors/<int:id>/', DoctorRetrieveUpdateDestroyView.as_view(), name='doctor-detail'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
