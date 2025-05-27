from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import UserSerializer, LoginSerializer, VerificationRequestSerializer, OrderSerializer
from .models import User, VerificationRequest, Order
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from rest_framework.decorators import api_view


# Create a JWT token for the user
def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=1),  # Token expires in 1 day
        'iat': datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token


class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                login(request, user)
                
                # Generate JWT token
                token = generate_jwt_token(user)
                
                # Return user data and token
                return Response({
                    'user': UserSerializer(user).data,
                    'token': token
                })
            else:
                return Response(
                    {'error': 'Invalid credentials'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        logout(request)
        return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)


class UserView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

class VerificationView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get status filter from query params, default to 'all'
        status_filter = request.query_params.get('status', 'all')
        
        # Filter verification requests based on status
        if status_filter == 'all':
            verification_requests = VerificationRequest.objects.all()
        elif status_filter == 'approved':
            verification_requests = VerificationRequest.objects.filter(status=VerificationRequest.Status.APPROVED)
        elif status_filter == 'pending':
            verification_requests = VerificationRequest.objects.filter(status=VerificationRequest.Status.PENDING)
        elif status_filter == 'rejected':
            verification_requests = VerificationRequest.objects.filter(status=VerificationRequest.Status.REJECTED)
        else:
            verification_requests = VerificationRequest.objects.all()
        
        # Serialize the verification requests
        serializer = VerificationRequestSerializer(verification_requests, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        request.data['patient'] = request.user.id
        serializer = VerificationRequestSerializer(data=request.data)
        if serializer.is_valid():
            # Set the patient to the current user if not provided
            if 'patient' not in serializer.validated_data and request.user.role == 'patient':
                serializer.validated_data['patient'] = request.user
            
            verification_request = serializer.save()
            return Response(VerificationRequestSerializer(verification_request).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerificationDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk):
        try:
            return VerificationRequest.objects.get(pk=pk)
        except VerificationRequest.DoesNotExist:
            return None
    
    def get(self, request, pk):
        verification_request = self.get_object(pk)
        if verification_request is None:
            return Response({'error': 'Verification request not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = VerificationRequestSerializer(verification_request)
        return Response(serializer.data)
    
    def put(self, request, pk):
        verification_request = self.get_object(pk)
        if verification_request is None:
            return Response({'error': 'Verification request not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = VerificationRequestSerializer(verification_request, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerificationApproveView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        # Only admins can approve verification requests
        if request.user.role != 'admin':
            return Response({'error': 'Only admins can approve verification requests'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            verification_request = VerificationRequest.objects.get(pk=pk)
        except VerificationRequest.DoesNotExist:
            return Response({'error': 'Verification request not found'}, status=status.HTTP_404_NOT_FOUND)
        
        verification_request.status = VerificationRequest.Status.APPROVED
        verification_request.save()
        
        serializer = VerificationRequestSerializer(verification_request)
        return Response(serializer.data)

class VerificationRejectView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        # Only admins can reject verification requests
        if request.user.role != 'admin':
            return Response({'error': 'Only admins can reject verification requests'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            verification_request = VerificationRequest.objects.get(pk=pk)
        except VerificationRequest.DoesNotExist:
            return Response({'error': 'Verification request not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get rejection reason from request data
        rejection_reason = request.data.get('rejection_reason', '')
        
        verification_request.status = VerificationRequest.Status.REJECTED
        verification_request.rejection_reason = rejection_reason
        verification_request.save()
        
        serializer = VerificationRequestSerializer(verification_request)
        return Response(serializer.data)


class OrderView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get status filter from query params, default to 'all'
        status_filter = request.query_params.get('status', 'all')
        
        # Filter orders based on status
        if status_filter == 'all':
            orders = Order.objects.all()
        else:
            orders = Order.objects.filter(status=status_filter)
        
        # Serialize the orders
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        # Create a new order
        serializer = OrderSerializer(data=request.data)
        if serializer.is_valid():
            order = serializer.save()
            return Response(OrderSerializer(order).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OrderDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk):
        try:
            return Order.objects.get(pk=pk)
        except Order.DoesNotExist:
            return None
    
    def get(self, request, pk):
        order = self.get_object(pk)
        if order is None:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = OrderSerializer(order)
        return Response(serializer.data)
    
    def put(self, request, pk):
        order = self.get_object(pk)
        if order is None:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = OrderSerializer(order, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OrderStatusUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk, status_value):
        # Only admins can update order status
        if request.user.role != 'admin':
            return Response({'error': 'Only admins can update order status'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            order = Order.objects.get(pk=pk)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Validate status value
        valid_statuses = [choice[0] for choice in Order.Status.choices]
        if status_value not in valid_statuses:
            return Response({'error': f'Invalid status. Must be one of {valid_statuses}'}, status=status.HTTP_400_BAD_REQUEST)
        
        order.status = status_value
        order.save()
        
        serializer = OrderSerializer(order)
        return Response(serializer.data)

@api_view(['GET'])
def dashboard_stats(request):
    pending_verifications = VerificationRequest.objects.filter(
        status=VerificationRequest.Status.PENDING
    ).count()
    total_orders = Order.objects.count()
    recent_verifications = VerificationRequest.objects.order_by('-submitted_date')[:5]

    return Response({
        'pending_verifications': pending_verifications,
        'total_orders': total_orders,
        'recent_verifications': [
            {
                'patient_name': ver.patient_name,
                'insurance_provider': ver.insurance_provider,
                'status': ver.status,
                'submitted_date': ver.submitted_date
            } for ver in recent_verifications
        ]
    })
