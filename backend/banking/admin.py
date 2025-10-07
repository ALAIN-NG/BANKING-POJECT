from django.contrib import admin
from .models import CustomUser, BankAccount, Transaction, BankCard, AuditLog


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
