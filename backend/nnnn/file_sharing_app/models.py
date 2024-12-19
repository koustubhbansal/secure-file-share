from django.db import models
from django.contrib.auth.models import AbstractUser
from cryptography.fernet import Fernet
from shorturls.models import ShortURL


class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('regular', 'Regular User'),
        ('guest', 'Guest'),
    ]

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='regular')
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.email

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='files/')
    encrypted_file = models.FileField(upload_to='encrypted_files/')
    upload_date = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        with open(self.file.path, 'rb') as file:
            encrypted_data = cipher_suite.encrypt(file.read())
        with open(self.encrypted_file.path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        super().save(*args, **kwargs)

class Permission(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    permission = models.CharField(max_length=10)  # e.g., 'view', 'download'

class SharedFile(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    permission = models.CharField(max_length=10, choices=['view', 'download'])
    short_url = models.OneToOneField(ShortURL, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        short_url = ShortURL.objects.create()
        self.short_url = short_url
        super().save(*args, **kwargs)

