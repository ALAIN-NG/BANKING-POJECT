from django.contrib import admin
from .models import (
    CustomUser, BankAccount, Transaction,
    BankCard, AuditLog, Loan, LoanPayment,
    Notification, EmployeeProfile, Device,
    BackupJob, AMLCheck
)


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "full_name", "role", "is_active", "is_superuser")
    list_filter = ("role", "is_active", "is_superuser")
    search_fields = ("email", "username", "full_name")


@admin.register(BankAccount)
class BankAccountAdmin(admin.ModelAdmin):
    list_display = ("account_number", "owner", "balance", "currency", "is_active", "created_at")
    list_filter = ("currency", "is_active")
    search_fields = ("account_number", "owner__email")


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "type",
        "amount",
        "status",
        "from_account",
        "to_account",
        "created_at",
        "completed_at")
    list_filter = ("type", "status")
    search_fields = ("id", "from_account__account_number", "to_account__account_number")
    date_hierarchy = "created_at"


@admin.register(BankCard)
class BankCardAdmin(admin.ModelAdmin):
    list_display = ("card_holder", "brand", "last4", "expiry_month", "expiry_year", "account")
    search_fields = ("last4", "account__account_number", "card_holder")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "action", "ip_address")
    list_filter = ("action",)
    search_fields = ("user__email", "action", "details")
    date_hierarchy = "timestamp"


@admin.register(Loan)
class LoanAdmin(admin.ModelAdmin):
    list_display = ("id", "applicant", "amount", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("applicant__email", "id")


@admin.register(LoanPayment)
class LoanPaymentAdmin(admin.ModelAdmin):
    list_display = ("id", "loan", "amount", "paid_at")
    search_fields = ("loan__id",)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "channel", "status", "created_at")
    list_filter = ("channel", "status")
    search_fields = ("user__email", "subject")


@admin.register(EmployeeProfile)
class EmployeeProfileAdmin(admin.ModelAdmin):
    list_display = ("employee_id", "user", "branch", "job_title")


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "device_id", "last_seen", "trusted")
    search_fields = ("device_id", "user__email")


@admin.register(BackupJob)
class BackupJobAdmin(admin.ModelAdmin):
    list_display = ("id", "initiated_by", "status", "created_at")


@admin.register(AMLCheck)
class AMLCheckAdmin(admin.ModelAdmin):
    list_display = ("id", "checked_object_type", "checked_object_id", "provider", "status", "created_at")
    search_fields = ("checked_object_id",)
