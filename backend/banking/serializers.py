from rest_framework import serializers
from .models import (
    Loan, LoanPayment, Notification, EmployeeProfile,
    Device, BackupJob, AMLCheck, CustomUser, BankAccount,
    Transaction, BankCard, ImpersonationLog
)


# ----------------------------------
# User Serializer
# ----------------------------------
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "full_name", "role", "is_email_verified"]
        read_only_fields = ["id"]


# ----------------------------------
# Bank Account Serializers
# ----------------------------------
class BankAccountSerializer(serializers.ModelSerializer):
    owner_email = serializers.CharField(source="owner.email", read_only=True)

    class Meta:
        model = BankAccount
        fields = [
            "id", "owner", "owner_email", "account_number", "balance",
            "currency", "is_active", "created_at", "metadata"
        ]
        read_only_fields = ["id", "account_number", "created_at"]

    def validate_balance(self, value):
        if value < 0:
            raise serializers.ValidationError("Le solde ne peut pas être négatif.")
        return value


# ----------------------------------
# Transaction Serializers
# ----------------------------------
class TransactionSerializer(serializers.ModelSerializer):
    from_account_number = serializers.CharField(source="from_account.account_number", read_only=True)
    to_account_number = serializers.CharField(source="to_account.account_number", read_only=True)
    created_by_email = serializers.CharField(source="created_by.email", read_only=True)

    class Meta:
        model = Transaction
        fields = [
            "id", "created_at", "completed_at", "from_account", "from_account_number",
            "to_account", "to_account_number", "to_account_number", "amount", "type",
            "status", "description", "created_by", "created_by_email"
        ]
        read_only_fields = ["id", "created_at", "completed_at"]

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Le montant doit être supérieur à 0.")
        return value


# ----------------------------------
# Bank Card Serializer
# ----------------------------------
class BankCardSerializer(serializers.ModelSerializer):
    account_number = serializers.CharField(source="account.account_number", read_only=True)

    class Meta:
        model = BankCard
        fields = [
            "id", "account", "account_number", "card_holder", "brand",
            "last4", "expiry_month", "expiry_year", "token", "created_at"
        ]
        read_only_fields = ["id", "created_at"]


# ----------------------------------
# Loan Serializers
# ----------------------------------
class LoanPaymentSerializer(serializers.ModelSerializer):
    created_by_email = serializers.CharField(source="created_by.email", read_only=True)

    class Meta:
        model = LoanPayment
        fields = ["id", "loan", "amount", "paid_at", "created_by", "created_by_email"]
        read_only_fields = ["id", "paid_at"]


class LoanSerializer(serializers.ModelSerializer):
    payments = LoanPaymentSerializer(many=True, read_only=True)
    applicant_email = serializers.CharField(source="applicant.email", read_only=True)
    created_by_email = serializers.CharField(source="created_by.email", read_only=True)

    class Meta:
        model = Loan
        fields = [
            "id", "applicant", "applicant_email", "amount", "term_months", "interest_rate",
            "monthly_payment", "outstanding_amount", "status", "created_at",
            "approved_at", "submitted_at", "notes", "metadata", "payments"
        ]
        read_only_fields = ["id", "created_at", "approved_at", "submitted_at"]

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Montant du prêt invalide.")
        return value

    def validate_interest_rate(self, value):
        if value < 0:
            raise serializers.ValidationError("Le taux d'intérêt ne peut pas être négatif.")
        return value


# ----------------------------------
# Notification Serializer
# ----------------------------------
class NotificationSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Notification
        fields = [
            "id", "user", "user_email", "channel", "subject", "body",
            "payload", "status", "created_at", "sent_at"
        ]
        read_only_fields = ["id", "created_at", "sent_at"]


# ----------------------------------
# Employee Profile Serializer
# ----------------------------------
class EmployeeProfileSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)
    user_full_name = serializers.CharField(source="user.full_name", read_only=True)

    class Meta:
        model = EmployeeProfile
        fields = [
            "id", "user", "user_email", "user_full_name", "employee_id",
            "branch", "job_title", "is_privileged", "hired_at", "metadata"
        ]
        read_only_fields = ["id"]


# ----------------------------------
# Device Serializer
# ----------------------------------
class DeviceSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Device
        fields = [
            "id", "user", "user_email", "device_id", "user_agent",
            "ip_address", "last_seen", "trusted", "metadata"
        ]
        read_only_fields = ["id", "last_seen"]


# ----------------------------------
# Backup Jobs Serializer
# ----------------------------------
class BackupJobSerializer(serializers.ModelSerializer):
    initiated_by_email = serializers.CharField(source="initiated_by.email", read_only=True)

    class Meta:
        model = BackupJob
        fields = [
            "id", "initiated_by", "initiated_by_email", "status",
            "started_at", "finished_at", "result", "created_at"
        ]
        read_only_fields = ["id", "created_at"]


# ----------------------------------
# AML Check Serializer
# ----------------------------------
class AMLCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = AMLCheck
        fields = [
            "id", "checked_object_type", "checked_object_id",
            "provider", "result", "status", "created_at"
        ]
        read_only_fields = ["id", "created_at"]


# ----------------------------------
# Impersonation Log Serializer
# ----------------------------------
class ImpersonationLogSerializer(serializers.ModelSerializer):
    impersonator_email = serializers.CharField(source="impersonator.email", read_only=True)
    target_email = serializers.CharField(source="target.email", read_only=True)
    terminated_by_email = serializers.CharField(source="terminated_by.email", read_only=True)

    class Meta:
        model = ImpersonationLog
        fields = [
            "id", "impersonator", "impersonator_email", "target", "target_email",
            "reason", "start_time", "end_time", "start_ip", "end_ip",
            "start_user_agent", "end_user_agent", "terminated_by", "terminated_by_email", "metadata"
        ]
        read_only_fields = ["id", "start_time"]
