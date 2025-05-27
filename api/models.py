from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    """Custom user manager for the User model."""
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular user with the given email and password."""
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom user model with email as the unique identifier."""
    
    class Role(models.TextChoices):
        ADMIN = 'admin', _('Admin')
        PATIENT = 'patient', _('Patient')
    
    username = None
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=150)
    last_name = models.CharField(_('last name'), max_length=150)
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.PATIENT,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email


class VerificationRequest(models.Model):
    """Model for patient verification requests."""
    
    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        APPROVED = 'approved', _('Approved')
        REJECTED = 'rejected', _('Rejected')
    
    class Priority(models.TextChoices):
        URGENT = 'urgent', _('Urgent')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
    
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_requests')
    patient_name = models.CharField(max_length=255)
    date_of_birth = models.DateField()
    insurance_provider = models.CharField(max_length=255)
    submitted_by = models.CharField(max_length=255)
    submitted_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.PENDING,
    )
    priority = models.CharField(
        max_length=10,
        choices=Priority.choices,
        default=Priority.MEDIUM,
    )
    condition = models.CharField(max_length=255)
    wound_location = models.CharField(max_length=255, blank=True, null=True)
    wound_size = models.CharField(max_length=100, blank=True, null=True)
    wound_duration = models.CharField(max_length=100, blank=True, null=True)
    current_treatment = models.TextField(blank=True, null=True)
    is_infected = models.BooleanField(default=False)
    is_draining = models.BooleanField(default=False)
    stage = models.CharField(max_length=100, blank=True, null=True)
    rejection_reason = models.TextField(blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    service_address = models.TextField(blank=True, null=True)
    secondary_insurance = models.CharField(max_length=255, blank=True, null=True)
    provider_name = models.CharField(max_length=255, blank=True, null=True)
    facility = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"Verification Request {self.id} - {self.patient_name}"


class Order(models.Model):
    """Model for patient orders."""
    
    class Status(models.TextChoices):
        SUBMITTED = 'submitted', _('Submitted')
        PROCESSING = 'processing', _('Processing')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')
    
    class Priority(models.TextChoices):
        URGENT = 'urgent', _('Urgent')
        HIGH = 'high', _('High')
        NORMAL = 'normal', _('Normal')
        LOW = 'low', _('Low')

    patient_name = models.CharField(max_length=255)
    order_type = models.CharField(max_length=100)
    order_description = models.TextField()
    priority = models.CharField(
        max_length=10,
        choices=Priority.choices,
        default=Priority.NORMAL,
    )
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.SUBMITTED,
    )
    submitted_by = models.CharField(max_length=255)
    submitted_date = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Order {self.id} - {self.patient_name}"
