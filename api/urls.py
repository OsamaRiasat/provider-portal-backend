from django.urls import path
from .views import *

urlpatterns = [
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/user/', UserView.as_view(), name='user'),
    path('verification/', VerificationView.as_view(), name='verification'),
    path('verification/<str:pk>/', VerificationDetailView.as_view(), name='verification-detail'),
    path('verification/<str:pk>/approve/', VerificationApproveView.as_view(), name='verification-approve'),
    path('verification/<str:pk>/reject/', VerificationRejectView.as_view(), name='verification-reject'),
    path('orders/', OrderView.as_view(), name='orders'),
    path('orders/<str:pk>/', OrderDetailView.as_view(), name='order-detail'),
    path('orders/<str:pk>/status/<str:status_value>/', OrderStatusUpdateView.as_view(), name='order-status-update'),
    path('dashboard-stats/', dashboard_stats, name='dashboard-stats'),
]
