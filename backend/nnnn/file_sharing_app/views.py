# file_sharing_app/views.py
from datetime import datetime, timezone
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .models import User, File, Permission
from .serializers import UserSerializer, FileSerializer, PermissionSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from cryptography.fernet import Fernet
from shorturls.views import get_short_url
from file_sharing_app.models import SharedFile

# views.py
from django_otp.decorators import otp_required

# views.py
from rest_framework.permissions import IsAuthenticated

class AdminView(APIView):
    permission_classes = [IsAuthenticated]

    def has_permission(self, request, view):
        if request.user.role == 'admin':
            return True
        return False

    def get(self, request):
        # Implement admin-specific logic here
        return Response({'message': 'Hello, Admin!'}, status=status.HTTP_200_OK)

class RegularUserView(APIView):
    permission_classes = [IsAuthenticated]

    def has_permission(self, request, view):
        if request.user.role == 'regular':
            return True
        return False

    def get(self, request):
        # Implement regular user-specific logic here
        return Response({'message': 'Hello, Regular User!'}, status=status.HTTP_200_OK)

class GuestView(APIView):
    permission_classes = [IsAuthenticated]

    def has_permission(self, request, view):
        if request.user.role == 'guest':
            return True
        return False

    def get(self, request):
        # Implement guest-specific logic here
        return Response({'message': 'Hello, Guest!'}, status=status.HTTP_200_OK)

class MFALoginView(APIView):
    @otp_required
    def post(self, request):
        # Implement MFA-specific logic here
        return Response({'message': 'Hello, User!'}, status=status.HTTP_200_OK)

class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects.filter(email=email).first()
        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class UserLogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class FileUploadView(APIView):
    def post(self, request):
        serializer = FileSerializer(data=request.data)
        if serializer.is_valid():
            file = serializer.save(user=request.user)
            return Response({'message': 'File uploaded successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FileDownloadView(APIView):
    def get(self, request, file_id):
        file = File.objects.get(id=file_id)
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        with open(file.encrypted_file.path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return Response(decrypted_data, content_type='application/octet-stream')

class FileShareView(APIView):
    def post(self, request, file_id):
        file = File.objects.filter(id=file_id).first()
        if file and file.user == request.user:
            permission = Permission.objects.create(file=file, user=request.data.get('user'), permission=request.data.get('permission'))
            return Response({'message': 'File shared successfully'}, status=status.HTTP_201_CREATED)
        return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

class PermissionView(APIView):
    def get(self, request, file_id):
        file = File.objects.filter(id=file_id).first()
        if file and file.user == request.user:
            permissions = Permission.objects.filter(file=file)
            serializer = PermissionSerializer(permissions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

class ShareFileView(APIView):
    def post(self, request, file_id):
        file = File.objects.get(id=file_id)
        user = request.user
        permission = request.data.get('permission')
        shared_file = SharedFile.objects.create(file=file, user=user, permission=permission)
        short_url = get_short_url(shared_file.short_url)
        return Response({'short_url': short_url, 'expires_at': shared_file.expires_at})

class SharedFileView(APIView):
    def get(self, request, short_url):
        shared_file = SharedFile.objects.get(short_url__short_url=short_url)
        if shared_file.expires_at < datetime.now():
            return Response({'error': 'Link has expired'}, status=404)
        file = shared_file.file
        if shared_file.permission == 'view':
            return Response({'file': file.file}, content_type='application/octet-stream')
        elif shared_file.permission == 'download':
            return Response({'file': file.file}, content_type='application/octet-stream')
        
    def post(self, request, file_id):
        file = File.objects.get(id=file_id)
        user = request.user
        permission = request.data.get('permission')
        expires_at = request.data.get('expires_at')
        if expires_at is None:
            expires_at = timezone.now() + timezone.timedelta(hours=1)
        shared_file = SharedFile.objects.create(file=file, user=user, permission=permission, expires_at=expires_at)
        short_url = get_short_url(shared_file.short_url)
        return Response({'short_url': short_url, 'expires_at': shared_file.expires_at})