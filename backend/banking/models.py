"""
Modèles principaux pour l'application bancaire.

- CustomUser: hérite de AbstractUser, utilise email unique et rôles.
- BankAccount: comptes bancaires, opérations atomiques (deposit/withdraw/transfer).
- Transaction: enregistre toutes les transactions avec statut et contrôles.
- BankCard: stockage sécurisé minimal (no CVV), prévu pour tokenization.
- AuditLog: journal immutable des actions critiques.

Notes:
- Ne stockez jamais de CVV en clair. Utilisez un service de tokenization PCI-compliant.
- Toutes les modifications de solde se font dans des transactions DB atomiques.
"""

from __future__ import annotations

import uuid
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from typing import Optional

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

# -------------------------
# Constants / Helpers
# -------------------------
ACCOUNT_NUMBER_LENGTH = 10  # ex: 10 digits
DEFAULT_CURRENCY = "XAF"
DECIMAL_PLACES = 2
MAX_DIGITS = 20  # allow very large balances if needed


def quantize_amount(amount: Decimal) -> Decimal:
    """Normalise un Decimal au format utilisé par les montants (2 décimales)."""
    try:
        return amount.quantize(Decimal(f"1.{'0'*DECIMAL_PLACES}"), rounding=ROUND_DOWN)
    except (InvalidOperation, AttributeError) as e:
        raise ValidationError("Montant invalide") from e


def generate_account_number() -> str:
    """
    Génère un numéro de compte unique simple (peut être remplacé par une logique bancaire).
    Ici we use UUID4 hex truncated + numeric mapping to reach desired length.
    """
    # keep generating until unique (low collision probability)
    while True:
        candidate = str(uuid.uuid4().int)[-ACCOUNT_NUMBER_LENGTH:]
        if not BankAccount.objects.filter(account_number=candidate).exists():
            return candidate


# -------------------------
# User
# -------------------------
class CustomUser(AbstractUser):
    """
    Utiliser email comme identifiant secondaire. Garder username pour compatibilité admin.
    Ajout d'un champ 'role' pour RBAC minimal.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, null=False, blank=False)
    full_name = models.CharField(max_length=255, blank=True)
    ROLE_CLIENT = "client"
    ROLE_TELLER = "teller"
    ROLE_MANAGER = "manager"
    ROLE_ADMIN = "admin"
    ROLE_CHOICES = [
        (ROLE_CLIENT, "Client"),
        (ROLE_TELLER, "Teller"),
        (ROLE_MANAGER, "Manager"),
        (ROLE_ADMIN, "Admin"),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_CLIENT)
    is_email_verified = models.BooleanField(default=False)
    # example KYC document path stored in media with proper access controls
    kyc_document = models.CharField(max_length=1024, blank=True, null=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["role"]),
        ]

    def __str__(self):
        return self.email or self.username


# -------------------------
# Audit Log
# -------------------------
class AuditLog(models.Model):
    """
    Journal immuable des actions critiques (sécurité / conformité).
    Stocker un enregistrement lisible : qui, action, détails, ip/time.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=128)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["action"]),
            models.Index(fields=["user"]),
        ]

    def __str__(self):
        who = self.user.email if self.user else "system"
        return f"[{self.timestamp.isoformat()}] {who}: {self.action}"


# -------------------------
# Bank Account
# -------------------------
class BankAccount(models.Model):
    """
    Représente un compte bancaire.
    - balance: Decimal stored in normalized form.
    - account_number: string unique (format configurable).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="accounts", on_delete=models.CASCADE)
    account_number = models.CharField(max_length=ACCOUNT_NUMBER_LENGTH, unique=True, db_index=True)
    balance = models.DecimalField(max_digits=MAX_DIGITS, decimal_places=DECIMAL_PLACES, default=Decimal("0.00"))
    currency = models.CharField(max_length=8, default=DEFAULT_CURRENCY)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    metadata = models.JSONField(default=dict, blank=True)  # store non-sensitive metadata

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.account_number} ({self.owner.email})"

    def clean(self):
        # ensure balance quantization
        self.balance = quantize_amount(Decimal(self.balance))

    def save(self, *args, **kwargs):
        if not self.account_number:
            self.account_number = generate_account_number()
        self.full_clean()
        return super().save(*args, **kwargs)

    # -------------
    # Balance ops (safe)
    # -------------
    def deposit(self, amount: Decimal, *, by_user: Optional[CustomUser] = None, description: str = "") -> "Transaction":
        """Crée une transaction de type 'deposit' et exécute l'opération de façon atomique."""
        amount = quantize_amount(Decimal(amount))
        if amount <= Decimal("0.00"):
            raise ValidationError("Le montant du dépôt doit être > 0")

        with transaction.atomic():
            # lock account row for update
            acc = BankAccount.objects.select_for_update().get(pk=self.pk)
            tx = Transaction.objects.create(
                from_account=None,
                to_account=acc,
                to_account_number=acc.account_number,
                amount=amount,
                type=Transaction.TYPE_DEPOSIT,
                status=Transaction.STATUS_PENDING,
                created_by=by_user
            )
            # update balance and mark tx completed
            acc.balance = quantize_amount(acc.balance + amount)
            acc.save(update_fields=["balance"])
            tx.status = Transaction.STATUS_COMPLETED
            tx.completed_at = timezone.now()
            tx.save(update_fields=["status", "completed_at"])
            AuditLog.objects.create(user=by_user, action="deposit", details=f"{amount} to {acc.account_number}")
            return tx

    def withdraw(self, amount: Decimal, *, by_user: Optional[CustomUser] = None, description: str = "") -> "Transaction":
        """Effectue un retrait si solde suffisant; op atomique."""
        amount = quantize_amount(Decimal(amount))
        if amount <= Decimal("0.00"):
            raise ValidationError("Le montant du retrait doit être > 0")

        with transaction.atomic():
            acc = BankAccount.objects.select_for_update().get(pk=self.pk)
            if acc.balance < amount:
                # record failed transaction for audit
                tx = Transaction.objects.create(
                    from_account=acc,
                    to_account=None,
                    to_account_number="",
                    amount=amount,
                    type=Transaction.TYPE_WITHDRAWAL,
                    status=Transaction.STATUS_FAILED,
                    created_by=by_user
                )
                AuditLog.objects.create(user=by_user, action="withdraw_failed", details=f"insufficient funds {acc.account_number}")
                raise ValidationError("Fonds insuffisants")
            tx = Transaction.objects.create(
                from_account=acc,
                to_account=None,
                to_account_number="",
                amount=amount,
                type=Transaction.TYPE_WITHDRAWAL,
                status=Transaction.STATUS_PENDING,
                created_by=by_user
            )
            acc.balance = quantize_amount(acc.balance - amount)
            acc.save(update_fields=["balance"])
            tx.status = Transaction.STATUS_COMPLETED
            tx.completed_at = timezone.now()
            tx.save(update_fields=["status", "completed_at"])
            AuditLog.objects.create(user=by_user, action="withdraw", details=f"{amount} from {acc.account_number}")
            return tx

    def transfer_to(self, to_account: "BankAccount", amount: Decimal, *, by_user: Optional[CustomUser] = None, description: str = "") -> "Transaction":
        """Transfert atomique entre comptes (débit source, crédit destination)."""
        if self.pk == to_account.pk:
            raise ValidationError("Impossible de transférer vers le même compte")
        amount = quantize_amount(Decimal(amount))
        if amount <= Decimal("0.00"):
            raise ValidationError("Montant invalide")

        # lock both accounts in deterministic order to avoid deadlocks
        ids = sorted([self.pk, to_account.pk])
        with transaction.atomic():
            # select_for_update for both rows
            accs = list(BankAccount.objects.select_for_update().filter(pk__in=ids).order_by("pk"))
            # map back to source/dest
            src = next(a for a in accs if a.pk == self.pk)
            dst = next(a for a in accs if a.pk == to_account.pk)
            if src.balance < amount:
                tx = Transaction.objects.create(
                    from_account=src,
                    to_account=dst,
                    to_account_number=dst.account_number,
                    amount=amount,
                    type=Transaction.TYPE_TRANSFER,
                    status=Transaction.STATUS_FAILED,
                    created_by=by_user
                )
                AuditLog.objects.create(user=by_user, action="transfer_failed", details=f"insufficient funds {src.account_number} -> {dst.account_number}")
                raise ValidationError("Fonds insuffisants pour le transfert")

            tx = Transaction.objects.create(
                from_account=src,
                to_account=dst,
                to_account_number=dst.account_number,
                amount=amount,
                type=Transaction.TYPE_TRANSFER,
                status=Transaction.STATUS_PENDING,
                created_by=by_user,
                description=description
            )
            src.balance = quantize_amount(src.balance - amount)
            dst.balance = quantize_amount(dst.balance + amount)
            src.save(update_fields=["balance"])
            dst.save(update_fields=["balance"])
            tx.status = Transaction.STATUS_COMPLETED
            tx.completed_at = timezone.now()
            tx.save(update_fields=["status", "completed_at"])
            AuditLog.objects.create(user=by_user, action="transfer", details=f"{amount} {src.account_number} -> {dst.account_number}")
            return tx


# -------------------------
# Transaction
# -------------------------
class Transaction(models.Model):
    """
    Enregistre une opération financière.
    Les champs from_account/to_account peuvent être null pour dépôt/retrait/externe.
    """
    TYPE_DEPOSIT = "deposit"
    TYPE_WITHDRAWAL = "withdrawal"
    TYPE_TRANSFER = "transfer"
    TYPE_CHOICES = [
        (TYPE_DEPOSIT, "Deposit"),
        (TYPE_WITHDRAWAL, "Withdrawal"),
        (TYPE_TRANSFER, "Transfer"),
    ]

    STATUS_PENDING = "pending"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True, db_index=True)

    from_account = models.ForeignKey(BankAccount, related_name="outgoing_transactions", null=True, blank=True, on_delete=models.SET_NULL)
    to_account = models.ForeignKey(BankAccount, related_name="incoming_transactions", null=True, blank=True, on_delete=models.SET_NULL)
    to_account_number = models.CharField(max_length=ACCOUNT_NUMBER_LENGTH, blank=True, db_index=True)

    amount = models.DecimalField(max_digits=MAX_DIGITS, decimal_places=DECIMAL_PLACES)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["type"]),
            models.Index(fields=["status"]),
            models.Index(fields=["created_by"]),
        ]

    def __str__(self):
        return f"Tx {self.id} {self.type} {self.amount} [{self.status}]"

    def clean(self):
        # ensure amount normalized
        self.amount = quantize_amount(Decimal(self.amount))
        if self.amount <= Decimal("0.00"):
            raise ValidationError("Montant doit être > 0")

    # Optionnel: method to attempt execution if created in pending state
    def execute(self):
        """
        Tentative d'exécution d'une transaction existante.
        - Ne pas appeler sans logique de verrouillage si concurrent.
        - Préférer les méthodes deposit/withdraw/transfer de BankAccount.
        """
        if self.status != Transaction.STATUS_PENDING:
            raise ValidationError("Transaction non en état pending")

        if self.type == Transaction.TYPE_DEPOSIT:
            if not self.to_account:
                raise ValidationError("Deposit requires to_account")
            return self.to_account.deposit(self.amount, by_user=self.created_by, description=self.description)

        if self.type == Transaction.TYPE_WITHDRAWAL:
            if not self.from_account:
                raise ValidationError("Withdrawal requires from_account")
            return self.from_account.withdraw(self.amount, by_user=self.created_by, description=self.description)

        if self.type == Transaction.TYPE_TRANSFER:
            if not (self.from_account and self.to_account):
                raise ValidationError("Transfer requires both from_account and to_account")
            return self.from_account.transfer_to(self.to_account, self.amount, by_user=self.created_by, description=self.description)


# -------------------------
# Bank Card
# -------------------------
class BankCard(models.Model):
    """
    Stockage minimal d'une carte :
    - Ne stocke PAS le CVV.
    - stocke last4, brand, expiry, and token (si tokenization via gateway).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(BankAccount, related_name="cards", on_delete=models.CASCADE)
    card_holder = models.CharField(max_length=255)
    brand = models.CharField(max_length=50, blank=True)  # Visa, Mastercard, etc.
    last4 = models.CharField(max_length=4)
    expiry_month = models.PositiveSmallIntegerField(null=True, blank=True)
    expiry_year = models.PositiveSmallIntegerField(null=True, blank=True)
    token = models.CharField(max_length=255, blank=True, help_text="Token issué par un service de paiement")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=["last4"]),
            models.Index(fields=["token"]),
        ]

    def __str__(self):
        return f"**** **** **** {self.last4} ({self.account.account_number})"
