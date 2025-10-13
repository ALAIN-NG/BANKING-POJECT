from rest_framework import serializers
from .models import (
    Loan, LoanPayment, Notification, EmployeeProfile,
    Device, BackupJob, AMLCheck
)


# ----------------------------------
# Loan Serializers
# ----------------------------------
class LoanPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoanPayment
        fields = ["id", "loan", "amount", "paid_at", "created_by"]


class LoanSerializer(serializers.ModelSerializer):
    payments = LoanPaymentSerializer(many=True, read_only=True)
    applicant_email = serializers.CharField(source="applicant.email", read_only=True)

    class Meta:
        model = Loan
        fields = [
            "id", "applicant_email", "amount", "term_months", "interest_rate",
            "monthly_payment", "outstanding_amount", "status", "created_at",
            "approved_at", "submitted_at", "payments"
        ]

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Montant du prêt invalide.")
        return value


# ----------------------------------
# Notification
# ----------------------------------
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["id", "subject", "body", "channel", "status", "created_at", "sent_at"]


# ----------------------------------
# Employee Profile
# ----------------------------------
class EmployeeProfileSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = EmployeeProfile
        fields = ["employee_id", "user_email", "branch", "job_title", "is_privileged", "hired_at"]


# ----------------------------------
# Devices
# ----------------------------------
class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ["id", "device_id", "user_agent", "ip_address", "last_seen", "trusted"]


# ----------------------------------
# Backup Jobs
# ----------------------------------
class BackupJobSerializer(serializers.ModelSerializer):
    initiated_by_email = serializers.CharField(source="initiated_by.email", read_only=True)

    class Meta:
        model = BackupJob
        fields = ["id", "initiated_by_email", "status", "started_at", "finished_at", "result", "created_at"]


# ----------------------------------
# AML Check
# ----------------------------------
class AMLCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = AMLCheck
        fields = ["id", "checked_object_type", "checked_object_id", "provider", "result", "status", "created_at"]
