# file_sharing_app/urls.py
from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserLogoutView, FileUploadView, FileDownloadView, FileShareView, PermissionView

urlpatterns = [
    path('register/', UserRegistrationView.as_view()),
    path('login/', UserLoginView.as_view()),
    path('logout/', UserLogoutView.as_view()),
    path('upload/', FileUploadView.as_view()),
    path('download/<int:file_id>/', FileDownloadView.as_view()),
    path('share/<int:file_id>/', FileShareView.as_view()),
    path('permissions/<int:file_id>/', PermissionView.as_view()),
]