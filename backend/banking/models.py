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
from django.db.models import JSONField, PositiveIntegerField, DateField, CharField, TextField, BooleanField


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


# -------------------------
# Loans
# -------------------------
class Loan(models.Model):
    """
    Représentation d'une demande / contrat de prêt.
    - amount: principal demandé
    - term_months: durée en mois
    - interest_rate: taux annuel en pourcentage (ex: 7.5)
    - status: draft -> submitted -> approved -> active -> closed -> rejected
    - payment_schedule: JSON optionnel (amortization schedule)
    """
    STATUS_DRAFT = "draft"
    STATUS_SUBMITTED = "submitted"
    STATUS_APPROVED = "approved"
    STATUS_ACTIVE = "active"
    STATUS_CLOSED = "closed"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = [
        (STATUS_DRAFT, "Draft"),
        (STATUS_SUBMITTED, "Submitted"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_ACTIVE, "Active"),
        (STATUS_CLOSED, "Closed"),
        (STATUS_REJECTED, "Rejected"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    applicant = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="loans", on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    amount = models.DecimalField(max_digits=MAX_DIGITS, decimal_places=DECIMAL_PLACES)
    term_months = PositiveIntegerField(default=12)
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal("0.00"))  # percent per year
    monthly_payment = models.DecimalField(max_digits=MAX_DIGITS, decimal_places=DECIMAL_PLACES, null=True, blank=True)
    outstanding_amount = models.DecimalField(max_digits=MAX_DIGITS, decimal_places=DECIMAL_PLACES, default=Decimal("0.00"))
    status = CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    notes = TextField(blank=True)
    metadata = JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["applicant"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"Loan {self.id} for {self.applicant.email} ({self.status})"

    def submit(self):
        if self.status != self.STATUS_DRAFT:
            raise ValidationError("Loan not in draft state")
        self.status = self.STATUS_SUBMITTED
        self.submitted_at = timezone.now()
        self.save()

    def approve(self, by_user=None):
        # basic approval workflow; in real life add underwriting checks
        if self.status not in (self.STATUS_SUBMITTED, self.STATUS_DRAFT):
            raise ValidationError("Loan not submittable/approvable")
        self.status = self.STATUS_APPROVED
        self.approved_at = timezone.now()
        # set outstanding and monthly_payment (simple amortization formula)
        principal = quantize_amount(Decimal(self.amount))
        r = Decimal(self.interest_rate) / Decimal("100.0") / Decimal("12.0")  # monthly rate
        n = int(self.term_months)
        if r == 0:
            monthly = (principal / n).quantize(Decimal(f"1.{'0'*DECIMAL_PLACES}"))
        else:
            # monthly payment = P * r / (1 - (1+r)^-n)
            monthly = (principal * r / (1 - (1 + r) ** (-n))).quantize(Decimal(f"1.{'0'*DECIMAL_PLACES}"))
        self.monthly_payment = monthly
        self.outstanding_amount = principal
        self.save()
        AuditLog.objects.create(user=by_user, action="loan_approved", details=f"Loan {self.id} approved")

    def activate(self, by_user=None):
        if self.status != self.STATUS_APPROVED:
            raise ValidationError("Only approved loans can be activated")
        self.status = self.STATUS_ACTIVE
        self.save()
        AuditLog.objects.create(user=by_user, action="loan_activated", details=f"Loan {self.id} activated")

    def register_payment(self, amount: Decimal, by_user=None):
        """Register a payment towards outstanding_amount."""
        amount = quantize_amount(Decimal(amount))
        if amount <= Decimal("0.00"):
            raise ValidationError("Montant de paiement invalide")
        if self.status != self.STATUS_ACTIVE:
            raise ValidationError("Loan not active")
        # Decrease outstanding
        self.outstanding_amount = quantize_amount(self.outstanding_amount - amount)
        if self.outstanding_amount <= Decimal("0.00"):
            self.outstanding_amount = Decimal("0.00")
            self.status = self.STATUS_CLOSED
            self.save()
            AuditLog.objects.create(user=by_user, action="loan_paid_off", details=f"Loan {self.id} paid off")
        else:
            self.save()
            AuditLog.objects.create(user=by_user, action="loan_payment", details=f"{amount} towards {self.id}")
        # create LoanPayment record
        lp = LoanPayment.objects.create(loan=self, paid_at=timezone.now(), amount=amount, created_by=by_user)
        return lp


class LoanPayment(models.Model):
    """Represents payments towards a loan."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    loan = models.ForeignKey(Loan, related_name="payments", on_delete=models.CASCADE)
    paid_at = models.DateTimeField(default=timezone.now)
    amount = models.DecimalField(max_digits=MAX_DIGITS, decimal_places=DECIMAL_PLACES)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-paid_at"]


# -------------------------
# Notifications
# -------------------------
class Notification(models.Model):
    """
    Notification sent to user (email, push, in-app).
    - channel: email/push/in-app
    - status: pending/sent/failed/read
    """
    CHANNEL_EMAIL = "email"
    CHANNEL_PUSH = "push"
    CHANNEL_INAPP = "inapp"
    CHANNEL_CHOICES = [
        (CHANNEL_EMAIL, "Email"),
        (CHANNEL_PUSH, "Push"),
        (CHANNEL_INAPP, "In-App"),
    ]

    STATUS_PENDING = "pending"
    STATUS_SENT = "sent"
    STATUS_FAILED = "failed"
    STATUS_READ = "read"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_SENT, "Sent"),
        (STATUS_FAILED, "Failed"),
        (STATUS_READ, "Read"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="notifications", on_delete=models.CASCADE)
    channel = CharField(max_length=20, choices=CHANNEL_CHOICES, default=CHANNEL_INAPP)
    subject = CharField(max_length=255, blank=True)
    body = TextField(blank=True)
    payload = JSONField(default=dict, blank=True)
    status = CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    created_at = models.DateTimeField(default=timezone.now)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user"]), models.Index(fields=["status"])]

    def mark_sent(self):
        self.status = self.STATUS_SENT
        self.sent_at = timezone.now()
        self.save()

    def mark_read(self):
        self.status = self.STATUS_READ
        self.save()


# -------------------------
# EmployeeProfile
# -------------------------
class EmployeeProfile(models.Model):
    """
    Extra profile for bank employees (tellers, managers).
    Stores employment metadata and optional permissions flags.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name="employee_profile", on_delete=models.CASCADE)
    employee_id = CharField(max_length=64, unique=True)
    branch = CharField(max_length=128, blank=True)
    job_title = CharField(max_length=128, blank=True)
    is_privileged = BooleanField(default=False)  # override RBAC for special tasks
    hired_at = DateField(null=True, blank=True)
    metadata = JSONField(default=dict, blank=True)

    class Meta:
        indexes = [models.Index(fields=["employee_id"]), models.Index(fields=["branch"])]


# -------------------------
# Device
# -------------------------
class Device(models.Model):
    """
    Track user devices/sessions (for device management, MFA, anomaly detection).
    - device_id: opaque id generated by client
    - last_seen: timestamp of last activity
    - trusted: boolean if device was explicitly trusted
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="devices", on_delete=models.CASCADE)
    device_id = CharField(max_length=256, db_index=True)
    user_agent = CharField(max_length=512, blank=True)
    ip_address = CharField(max_length=45, blank=True, null=True)
    last_seen = models.DateTimeField(default=timezone.now)
    trusted = BooleanField(default=False)
    metadata = JSONField(default=dict, blank=True)

    class Meta:
        indexes = [models.Index(fields=["user", "device_id"]), models.Index(fields=["trusted"])]


# -------------------------
# BackupJob
# -------------------------
class BackupJob(models.Model):
    """
    Tracking of backup/restore orchestrations.
    - status: queued -> running -> success -> failed
    - result: metadata about backup location
    """
    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_QUEUED)
    result = JSONField(default=dict, blank=True)  # e.g. {"path": "...", "size": 12345}
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]


# -------------------------
# AMLCheck
# -------------------------
class AMLCheck(models.Model):
    """
    AML / Screening record for a user or transaction. Integrate with external AML provider.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    checked_object_type = CharField(max_length=64)  # "user" or "transaction" or other
    checked_object_id = CharField(max_length=128)
    provider = CharField(max_length=128, blank=True)
    result = JSONField(default=dict, blank=True)
    status = CharField(max_length=32, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=["checked_object_type", "checked_object_id"])]


# -------------------------
# ImpersonationLog (audit dédié pour les sessions d'impersonation)
# -------------------------
class ImpersonationLog(models.Model):
    """
    Journalise les sessions d'impersonation :
    - impersonator : l'utilisateur qui a démarré l'impersonation
    - target : l'utilisateur cible
    - reason : raison donnée
    - start_time / end_time : bornes temporelles
    - start_ip / end_ip : IP de démarrage / fin
    - start_user_agent / end_user_agent : user agent
    - terminated_by : qui a arrêté l'impersonation (peut être l'impersonator ou système)
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    impersonator = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="impersonations_started", on_delete=models.SET_NULL, null=True)
    target = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="impersonations_target", on_delete=models.SET_NULL, null=True)
    reason = models.TextField(blank=True)
    start_time = models.DateTimeField(default=timezone.now, db_index=True)
    end_time = models.DateTimeField(null=True, blank=True, db_index=True)
    start_ip = models.GenericIPAddressField(blank=True, null=True)
    end_ip = models.GenericIPAddressField(blank=True, null=True)
    start_user_agent = models.CharField(max_length=512, blank=True)
    end_user_agent = models.CharField(max_length=512, blank=True)
    terminated_by = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="impersonations_terminated", on_delete=models.SET_NULL, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-start_time"]
        indexes = [
            models.Index(fields=["impersonator"]),
            models.Index(fields=["target"]),
        ]

    def __str__(self):
        return f"Impersonation {self.id} {self.impersonator} -> {self.target} ({self.start_time.isoformat()})"
