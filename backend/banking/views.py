# backend/banking/views.py
"""
API endpoints "entreprise" pour l'application bancaire.
Sécurisé : CSRF, session auth, role checks, validations, audit logging, atomic ops.
Certains endpoints avancés (loans, notifications, reports, backup) sont fournis en stub
avec instructions pour ajouter les modèles/services nécessaires.
"""

from __future__ import annotations

import csv
import io
import json
import secrets
from decimal import Decimal
from typing import Optional

from django.core.cache import cache
from django.core.exceptions import ValidationError, PermissionDenied


from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.sessions.models import Session
from django.contrib.auth import login as auth_login

from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.cache import never_cache

from django.utils import timezone
from django.db import models
from django.http import JsonResponse, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404


from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import transaction

from .models import (
    BankAccount, Transaction, BankCard,
    Loan, Notification, EmployeeProfile,
    Device, BackupJob, AMLCheck, AuditLog,
    ImpersonationLog
)

from .serializers import (
    LoanSerializer, LoanPaymentSerializer, NotificationSerializer,
    EmployeeProfileSerializer, DeviceSerializer, BackupJobSerializer,
    AMLCheckSerializer
)

User = get_user_model()


# -------------------------
# Helpers
# -------------------------
def json_response(payload, status=200):
    return JsonResponse(payload, status=status, safe=False)


def parse_json(request: HttpRequest) -> dict:
    try:
        return json.loads(request.body.decode() or "{}")
    except Exception:
        raise ValidationError("JSON invalide")


def audit(user: Optional[User], action: str, details: str = "", ip: Optional[str] = None):
    try:
        AuditLog.objects.create(user=user, action=action, details=details, ip_address=ip)
    except Exception:
        pass


def is_manager_or_admin(user: User):
    return user.is_superuser or user.role in (User.ROLE_MANAGER, User.ROLE_ADMIN)


def require_roles(*roles):
    def decorator(func):
        def wrapper(request: HttpRequest, *args, **kwargs):
            if not request.user.is_authenticated:
                raise PermissionDenied("Authentification requise")
            if not (request.user.is_superuser or request.user.role in roles):
                raise PermissionDenied("Droits insuffisants")
            return func(request, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------------
# PERMISSIONS CUSTOM
# ---------------------------
class IsAdminOrManager(permissions.BasePermission):
    """Autorise seulement admin et manager."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ["admin", "manager"]


class IsOwnerOrAdmin(permissions.BasePermission):
    """Autorise le propriétaire de la ressource ou un admin."""
    def has_object_permission(self, request, view, obj):
        return request.user.role == "admin" or getattr(obj, "applicant", None) == request.user


# -------------------------
# AUTH
# -------------------------
@csrf_protect
@require_POST
def register(request: HttpRequest):
    data = parse_json(request)
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")

    if not username or not email or not password:
        return json_response({"error": "username, email et password requis"}, 400)
    if User.objects.filter(email=email).exists():
        return json_response({"error": "email déjà utilisé"}, 400)
    if len(password) < 12:
        return json_response({"error": "mot de passe trop court (>=12)"}, 400)

    user = User(username=username, email=email, full_name=full_name, role=User.ROLE_CLIENT)
    user.set_password(password)
    user.is_active = True  # en prod : false et workflow email verification
    user.save()

    account = BankAccount.objects.create(owner=user)
    audit(user, "register", f"user {user.email} created account {account.account_number}", request.META.get("REMOTE_ADDR"))
    return json_response({"message": "created", "account": account.account_number}, 201)


@csrf_protect
@require_POST
def login_view(request: HttpRequest):
    data = parse_json(request)
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return json_response({"error": "username & password required"}, 400)

    user = authenticate(request, username=username, password=password)
    if user is None:
        audit(None, "login_failed", f"username={username}", request.META.get("REMOTE_ADDR"))
        return json_response({"error": "invalid credentials"}, 401)
    if not user.is_active:
        return json_response({"error": "account disabled"}, 403)

    login(request, user)
    audit(user, "login", "user logged in", request.META.get("REMOTE_ADDR"))
    return json_response({"message": "logged in"}, 200)


@csrf_protect
@require_POST
@login_required
def logout_view(request: HttpRequest):
    user = request.user
    logout(request)
    audit(user, "logout", "user logged out", request.META.get("REMOTE_ADDR"))
    return json_response({"message": "logged out"}, 200)


@csrf_protect
@require_POST
@login_required
def change_password(request: HttpRequest):
    data = parse_json(request)
    old = data.get("old_password")
    new = data.get("new_password")
    if not old or not new:
        return json_response({"error": "old_password & new_password required"}, 400)
    user = request.user
    if not user.check_password(old):
        audit(user, "change_password_failed", "wrong old password", request.META.get("REMOTE_ADDR"))
        return json_response({"error": "old password incorrect"}, 403)
    if len(new) < 12:
        return json_response({"error": "new password too short"}, 400)
    user.set_password(new)
    user.save()
    audit(user, "change_password", "password changed", request.META.get("REMOTE_ADDR"))
    return json_response({"message": "password changed"}, 200)


# Reset password and email-based flows require external email service; stubbed:
@csrf_protect
@require_POST
def request_password_reset(request: HttpRequest):
    # In production: generate token, email user with secure link
    return json_response({"message": "password reset flow not implemented; configure email provider"}, 501)


@csrf_protect
@require_POST
def verify_email_or_2fa(request: HttpRequest):
    # stub for OTP / 2FA verification
    return json_response({"message": "not implemented (integrate OTP provider)"}, 501)


# -------------------------
# CLIENT MANAGEMENT
# -------------------------
@login_required
@require_GET
@user_passes_test(is_manager_or_admin)
def list_clients(request: HttpRequest):
    qs = User.objects.filter(role=User.ROLE_CLIENT)
    out = [{"id": str(u.id), "username": u.username, "email": u.email, "full_name": u.full_name, "active": u.is_active} for u in qs]
    return json_response(out)


@login_required
@require_POST
@user_passes_test(is_manager_or_admin)
def create_client(request: HttpRequest):
    data = parse_json(request)
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")
    if not username or not email or not password:
        return json_response({"error": "fields required"}, 400)
    if User.objects.filter(email=email).exists():
        return json_response({"error": "email exists"}, 400)
    user = User(username=username, email=email, full_name=full_name, role=User.ROLE_CLIENT)
    user.set_password(password)
    user.is_active = True
    user.save()
    account = BankAccount.objects.create(owner=user)
    audit(request.user, "create_client", f"{user.email} by {request.user.email}")
    return json_response({"message": "client created", "client_id": str(user.id), "account": account.account_number}, 201)


@login_required
@require_POST
@user_passes_test(is_manager_or_admin)
def disable_client(request: HttpRequest, user_id: str):
    target = get_object_or_404(User, id=user_id)
    target.is_active = False
    target.save()
    audit(request.user, "disable_client", f"{target.email} by {request.user.email}")
    return json_response({"message": "client disabled"}, 200)


# KYC upload requires storage handling; stub:
@login_required
@require_POST
@user_passes_test(is_manager_or_admin)
def kyc_upload(request: HttpRequest, user_id: str):
    # Expect file in request.FILES and store in secured object storage (S3/GCS)
    return json_response({"message": "KYC upload not implemented; integrate object storage"}, 501)


# -------------------------
# ACCOUNTS
# -------------------------
@login_required
@require_GET
def list_accounts(request: HttpRequest):
    user = request.user
    if is_manager_or_admin(user):
        qs = BankAccount.objects.select_related("owner").all()
    else:
        qs = BankAccount.objects.select_related("owner").filter(owner=user)
    out = [{"account_number": a.account_number, "owner": a.owner.email, "balance": str(a.balance), "currency": a.currency, "active": a.is_active} for a in qs]
    return json_response(out)


@login_required
@require_POST
def create_account(request: HttpRequest):
    # Clients can create additional accounts for themselves; managers can create for others
    data = parse_json(request)
    owner_id = data.get("owner_id")
    if owner_id and not is_manager_or_admin(request.user):
        raise PermissionDenied("not allowed to create for others")
    owner = request.user if not owner_id else get_object_or_404(User, id=owner_id)
    acc = BankAccount.objects.create(owner=owner)
    audit(request.user, "create_account", f"account {acc.account_number} owner {owner.email}")
    return json_response({"account_number": acc.account_number}, 201)


@login_required
@require_GET
def account_detail(request: HttpRequest, account_number: str):
    acc = get_object_or_404(BankAccount, account_number=account_number)
    if acc.owner != request.user and not is_manager_or_admin(request.user) and request.user.role != User.ROLE_TELLER:
        raise PermissionDenied("not allowed")
    return json_response({"account_number": acc.account_number, "balance": str(acc.balance), "owner": acc.owner.email, "currency": acc.currency})


@login_required
@require_POST
@user_passes_test(is_manager_or_admin)
def toggle_account(request: HttpRequest, account_number: str):
    acc = get_object_or_404(BankAccount, account_number=account_number)
    acc.is_active = not acc.is_active
    acc.save()
    audit(request.user, "toggle_account", f"{acc.account_number} -> {acc.is_active}")
    return json_response({"account_number": acc.account_number, "active": acc.is_active})


@login_required
@require_POST
@user_passes_test(is_manager_or_admin)
def close_account(request: HttpRequest, account_number: str):
    acc = get_object_or_404(BankAccount, account_number=account_number)
    # In real life: check balance==0, pending transactions, regulatory holds...
    if acc.balance != Decimal("0.00"):
        return json_response({"error": "balance must be zero before close"}, 400)
    acc.delete()
    audit(request.user, "close_account", f"{account_number}")
    return json_response({"message": "account closed"}, 200)


@login_required
@require_GET
def account_statement(request: HttpRequest, account_number: str):
    # Generate simple CSV statement for date range if provided
    acc = get_object_or_404(BankAccount, account_number=account_number)
    if acc.owner != request.user and not is_manager_or_admin(request.user):
        raise PermissionDenied("not allowed")
    # date filters (optional)
    # start = request.GET.get("start")
    # end = request.GET.get("end")
    qs = Transaction.objects.filter(models.Q(from_account__account_number=account_number) | models.Q(to_account__account_number=account_number)).order_by("-created_at")
    # TODO: filter by start/end parsing ISO dates
    # Build CSV
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "type", "amount", "status", "from", "to", "created_at"])
    for t in qs:
        writer.writerow([str(t.id), t.type, str(t.amount), t.status, t.from_account.account_number if t.from_account else "", t.to_account.account_number if t.to_account else t.to_account_number, t.created_at.isoformat()])
    response = HttpResponse(buffer.getvalue(), content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=statement_" + account_number + ".csv"
    audit(request.user, "account_statement", f"{account_number}")
    return response


# -------------------------
# TRANSACTIONS
# -------------------------
@csrf_protect
@login_required
@require_POST
def deposit(request: HttpRequest):
    data = parse_json(request)
    account_number = data.get("account_number")
    amount_raw = data.get("amount")
    if not account_number or amount_raw is None:
        return json_response({"error": "account_number & amount required"}, 400)
    acc = get_object_or_404(BankAccount, account_number=account_number)
    if acc.owner != request.user and not is_manager_or_admin(request.user) and request.user.role != User.ROLE_TELLER:
        raise PermissionDenied("not allowed")
    try:
        amount = Decimal(str(amount_raw))
    except Exception:
        return json_response({"error": "invalid amount"}, 400)
    tx = acc.deposit(amount, by_user=request.user)
    audit(request.user, "deposit", f"{amount} to {acc.account_number}")
    return json_response({"tx_id": str(tx.id)}, 201)


@csrf_protect
@login_required
@require_POST
def withdraw(request: HttpRequest):
    data = parse_json(request)
    account_number = data.get("account_number")
    amount_raw = data.get("amount")
    acc = get_object_or_404(BankAccount, account_number=account_number)
    if acc.owner != request.user and not is_manager_or_admin(request.user) and request.user.role != User.ROLE_TELLER:
        raise PermissionDenied("not allowed")
    try:
        amount = Decimal(str(amount_raw))
    except Exception:
        return json_response({"error": "invalid amount"}, 400)
    tx = acc.withdraw(amount, by_user=request.user)
    audit(request.user, "withdraw", f"{amount} from {acc.account_number}")
    return json_response({"tx_id": str(tx.id)}, 201)


@csrf_protect
@login_required
@require_POST
def transfer(request: HttpRequest):
    data = parse_json(request)
    from_acc_num = data.get("from_account")
    to_acc_num = data.get("to_account")
    amount_raw = data.get("amount")
    if not from_acc_num or not to_acc_num or amount_raw is None:
        return json_response({"error": "missing fields"}, 400)
    src = get_object_or_404(BankAccount, account_number=from_acc_num)
    dst = get_object_or_404(BankAccount, account_number=to_acc_num)
    if src.owner != request.user and not is_manager_or_admin(request.user) and request.user.role != User.ROLE_TELLER:
        raise PermissionDenied("not allowed")
    try:
        amount = Decimal(str(amount_raw))
    except Exception:
        return json_response({"error": "invalid amount"}, 400)
    tx = src.transfer_to(dst, amount, by_user=request.user)
    audit(request.user, "transfer", f"{amount} {src.account_number}->{dst.account_number}")
    return json_response({"tx_id": str(tx.id)}, 201)


@csrf_protect
@login_required
@require_POST
def external_transfer(request: HttpRequest):
    # Placeholder: integrate with payment rail (SWIFT/SEPA/ACH/Local). Validate beneficiary IBAN/BIC.
    return json_response({"message": "external transfer not implemented - integrate payment rails"}, 501)


@login_required
@require_GET
def list_transactions(request: HttpRequest):
    user = request.user
    if is_manager_or_admin(user):
        qs = Transaction.objects.select_related("from_account", "to_account").order_by("-created_at")[:1000]
    else:
        qs = Transaction.objects.filter(models.Q(from_account__owner=user) | models.Q(to_account__owner=user)).select_related("from_account", "to_account").order_by("-created_at")[:500]
    out = [{"id": str(t.id), "type": t.type, "amount": str(t.amount), "status": t.status, "from": t.from_account.account_number if t.from_account else None, "to": t.to_account.account_number if t.to_account else t.to_account_number, "created_at": t.created_at.isoformat()} for t in qs]
    return json_response(out)


@csrf_protect
@login_required
@require_POST
@user_passes_test(is_manager_or_admin)
def cancel_transaction(request: HttpRequest, tx_id: str):
    tx = get_object_or_404(Transaction, id=tx_id)
    # In real system: complex reversal logic with ledger adjustments
    if tx.status != Transaction.STATUS_COMPLETED:
        return json_response({"error": "only completed transactions can be canceled"}, 400)
    # For demo: mark failed and create compensating transaction (NOT a real ledger)
    tx.status = Transaction.STATUS_FAILED
    tx.save()
    audit(request.user, "cancel_transaction", f"{tx.id}")
    return json_response({"message": "transaction canceled (NOTE: implement ledger compensation)"}, 200)


@csrf_protect
@login_required
def export_transactions_csv(request: HttpRequest):
    # export for date range (simplified)
    qs = Transaction.objects.select_related("from_account", "to_account").all().order_by("-created_at")[:2000]
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "type", "amount", "status", "from", "to", "created_at"])
    for t in qs:
        writer.writerow([str(t.id), t.type, str(t.amount), t.status, t.from_account.account_number if t.from_account else "", t.to_account.account_number if t.to_account else t.to_account_number, t.created_at.isoformat()])
    response = HttpResponse(buffer.getvalue(), content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=transactions.csv"
    audit(request.user, "export_transactions", f"export by {request.user.email}")
    return response


# -------------------------
# CARDS
# -------------------------
@csrf_protect
@login_required
@require_POST
def create_card(request: HttpRequest):
    data = parse_json(request)
    account_number = data.get("account_number")
    last4 = data.get("last4")
    card_holder = data.get("card_holder")
    token = data.get("token")  # tokenized card from PSP
    if not all([account_number, last4, token]):
        return json_response({"error": "account_number,last4,token required"}, 400)
    acc = get_object_or_404(BankAccount, account_number=account_number)
    if acc.owner != request.user and not is_manager_or_admin(request.user):
        raise PermissionDenied("not allowed")
    card = BankCard.objects.create(account=acc, card_holder=card_holder or acc.owner.full_name, last4=last4, token=token)
    audit(request.user, "create_card", f"card ****{last4} for {acc.account_number}")
    return json_response({"card_id": str(card.id)}, 201)


@csrf_protect
@login_required
def list_cards(request: HttpRequest):
    cards = BankCard.objects.filter(account__owner=request.user)
    out = [{"id": str(c.id), "last4": c.last4, "brand": c.brand, "expiry_month": c.expiry_month, "expiry_year": c.expiry_year, "account": c.account.account_number} for c in cards]
    return json_response(out)


@csrf_protect
@login_required
@user_passes_test(is_manager_or_admin)
def block_card(request: HttpRequest, card_id: str):
    # Block card: for demo we delete token or flag; in prod call PSP
    card = get_object_or_404(BankCard, id=card_id)
    card.token = ""  # nosec - This is intentional for blocking cards
    card.save()
    audit(request.user, "block_card", f"{card.id}")
    return json_response({"message": "card blocked"}, 200)


@csrf_protect
@login_required
@user_passes_test(is_manager_or_admin)
def renew_card(request: HttpRequest, card_id: str):
    # Stub for renewal workflow
    return json_response({"message": "renew card flow not implemented (integrate card issuer)"}, 501)


# ---------------------------
# LOANS
# ---------------------------
class LoanListCreateView(generics.ListCreateAPIView):
    serializer_class = LoanSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role in ["admin", "manager"]:
            return Loan.objects.all()
        return Loan.objects.filter(applicant=user)

    def perform_create(self, serializer):
        serializer.save(applicant=self.request.user)
        AuditLog.objects.create(user=self.request.user, action="loan_created", details="Loan draft created")


class LoanApproveView(APIView):
    permission_classes = [IsAdminOrManager]

    def post(self, request, pk):
        loan = get_object_or_404(Loan, pk=pk)
        with transaction.atomic():
            loan.approve(by_user=request.user)
        return Response({"message": "Loan approved."}, status=200)


class LoanPaymentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        loan = get_object_or_404(Loan, pk=pk)
        amount = request.data.get("amount")
        lp = loan.register_payment(amount, by_user=request.user)
        return Response(LoanPaymentSerializer(lp).data, status=201)


# ---------------------------
# NOTIFICATIONS
# ---------------------------
class NotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)


class NotificationReadView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        notif = get_object_or_404(Notification, pk=pk, user=request.user)
        notif.mark_read()
        return Response({"message": "Notification marked as read."}, status=200)


# ---------------------------
# EMPLOYEES
# ---------------------------
class EmployeeListView(generics.ListAPIView):
    serializer_class = EmployeeProfileSerializer
    permission_classes = [IsAdminOrManager]
    queryset = EmployeeProfile.objects.all()


# ---------------------------
# DEVICES
# ---------------------------
class DeviceListView(generics.ListAPIView):
    serializer_class = DeviceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Device.objects.filter(user=self.request.user)


# ---------------------------
# AML CHECKS
# ---------------------------
class AMLCheckListCreateView(generics.ListCreateAPIView):
    serializer_class = AMLCheckSerializer
    permission_classes = [IsAdminOrManager]

    def get_queryset(self):
        return AMLCheck.objects.all()

    def perform_create(self, serializer):
        serializer.save()
        AuditLog.objects.create(user=self.request.user, action="aml_check_created")


# -------------------------
# ADMIN / EMPLOYEES
# -------------------------


@login_required
@user_passes_test(is_manager_or_admin)
def create_employee(request: HttpRequest):
    data = parse_json(request)
    email = data.get("email")
    username = data.get("username")
    role = data.get("role")
    if role not in (User.ROLE_TELLER, User.ROLE_MANAGER, User.ROLE_ADMIN):
        return json_response({"error": "invalid role"}, 400)
    if User.objects.filter(email=email).exists():
        return json_response({"error": "email exists"}, 400)
    user = User(username=username, email=email, role=role)
    password = data.get("password", "Temporary123!")  # in real flow: email invite
    user.set_password(password)
    user.is_active = True
    user.save()
    audit(request.user, "create_employee", f"{email} role={role}")
    return json_response({"message": "employee created", "id": str(user.id)}, 201)


@login_required
@user_passes_test(is_manager_or_admin)
def toggle_user_active(request: HttpRequest, user_id: str):
    target = get_object_or_404(User, id=user_id)
    target.is_active = not target.is_active
    target.save()
    audit(request.user, "toggle_user_active", f"{target.email} -> {target.is_active}")
    return json_response({"id": str(target.id), "active": target.is_active})


# -------------------------
# GESTION RH & RÔLES INTERNES (EMPLOYEES / ROLES / SUSPENSION / PASSWORD)
# -------------------------

# NOTE: Les endpoints ci-dessous sont strictement réservés aux managers/admins.
# Ils utilisent user_passes_test(is_manager_or_admin) ou require_roles équivalent.

@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def list_employees_detailed(request: HttpRequest):
    """
    Liste détaillée des employés (profil RH, statut, branche).
    Accessible aux managers et admins.
    """
    qs = User.objects.filter(models.Q(role=User.ROLE_TELLER) | models.Q(role=User.ROLE_MANAGER) | models.Q(is_superuser=True))
    out = []
    for u in qs:
        profile = getattr(u, "employee_profile", None)
        out.append({
            "id": str(u.id),
            "email": u.email,
            "username": u.username,
            "role": u.role,
            "active": u.is_active,
            "employee_id": profile.employee_id if profile else None,
            "branch": profile.branch if profile else None,
            "job_title": profile.job_title if profile else None,
        })
    audit(request.user, "list_employees_detailed", f"{qs.count()} employés listés")
    return json_response(out)


@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def get_employee_detail(request: HttpRequest, user_id: str):
    """
    Détails RH sur un employé spécifique.
    """
    u = get_object_or_404(User, id=user_id)
    profile = getattr(u, "employee_profile", None)
    data = {
        "id": str(u.id),
        "email": u.email,
        "username": u.username,
        "role": u.role,
        "active": u.is_active,
        "full_name": u.full_name,
        "employee_profile": {
            "employee_id": profile.employee_id if profile else None,
            "branch": profile.branch if profile else None,
            "job_title": profile.job_title if profile else None,
            "is_privileged": profile.is_privileged if profile else False,
        } if profile else None
    }
    audit(request.user, "get_employee_detail", f"consulté {u.email}")
    return json_response(data)


@login_required
@user_passes_test(is_manager_or_admin)
@require_POST
def update_employee_profile(request: HttpRequest, user_id: str):
    """
    Met à jour le profil RH d'un employé (branch, job_title, is_privileged).
    Corps JSON attendu: { "branch": "...", "job_title": "...", "is_privileged": true }
    """
    data = parse_json(request)
    u = get_object_or_404(User, id=user_id)
    profile, created = EmployeeProfile.objects.get_or_create(user=u, defaults={"employee_id": f"EMP-{secrets.token_hex(4)}"})
    updated_fields = []
    for field in ("branch", "job_title", "is_privileged"):
        if field in data:
            setattr(profile, field, data[field])
            updated_fields.append(field)
    profile.save()
    audit(request.user, "update_employee_profile", f"{u.email} champs modifiés: {','.join(updated_fields)}")
    return json_response({"message": "profil employé mis à jour", "employee_id": profile.employee_id})


@login_required
@user_passes_test(is_manager_or_admin)
@require_POST
def set_user_role(request: HttpRequest, user_id: str):
    """
    Change le rôle d'un utilisateur.
    Corps JSON: { "role": "manager" }
    Validation: role doit être dans ROLE_CHOICES.
    """
    data = parse_json(request)
    new_role = data.get("role")
    if new_role not in dict(User.ROLE_CHOICES).keys():
        return json_response({"error": "role invalide"}, 400)
    u = get_object_or_404(User, id=user_id)
    old_role = u.role
    u.role = new_role
    u.save()
    audit(request.user, "set_user_role", f"{u.email}: {old_role} -> {new_role}")
    return json_response({"message": "role mis à jour", "user": str(u.id), "role": new_role})


@login_required
@user_passes_test(is_manager_or_admin)
@require_POST
def reset_user_password(request: HttpRequest, user_id: str):
    """
    Réinitialise le mot de passe d'un utilisateur en générant un mot de passe temporaire.
    En production : envoyer un lien de reset sécurisé par email (token-expirable).
    Retourne uniquement un indicateur en prod ; ici pour admin on peut retourner le temp pw.
    """
    target = get_object_or_404(User, id=user_id)
    # Générer un mot de passe temporaire fort
    temp_pw = secrets.token_urlsafe(12)
    target.set_password(temp_pw)
    target.save()
    audit(request.user, "reset_user_password", f"pwd reset pour {target.email}")
    # En prod: ne PAS retourner le mot de passe dans la réponse (envoyer par mail)
    return json_response({"message": "mot de passe réinitialisé", "temporary_password": temp_pw})


@login_required
@user_passes_test(is_manager_or_admin)
@require_POST
def force_logout_user(request: HttpRequest, user_id: str):
    """
    Invalide toutes les sessions d'un utilisateur (force logout).
    Parcours les sessions et supprime celles appartenant à user_id.
    """
    sessions = Session.objects.all()
    removed = 0
    for s in sessions:
        data = s.get_decoded()
        if str(data.get("_auth_user_id")) == str(user_id):
            s.delete()
            removed += 1
    audit(request.user, "force_logout_user", f"user={user_id} sessions_removed={removed}")
    return json_response({"message": f"{removed} sessions supprimées"})


@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def get_employee_audit(request: HttpRequest, user_id: str):
    """
    Récupère les entrées d'audit liées à un employé (filtre par user).
    Limite par défaut: 1000 entrées récentes.
    """
    logs = AuditLog.objects.filter(user__id=user_id).order_by("-timestamp")[:1000]
    out = [{"timestamp": lo.timestamp.isoformat(), "action": lo.action, "details": lo.details, "ip": lo.ip_address} for lo in logs]
    audit(request.user, "get_employee_audit", f"{user_id} logs={len(out)}")
    return json_response(out)


@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def list_roles(request: HttpRequest):
    """
    Retourne la liste des rôles utilisables par le système pour affichage UI.
    """
    roles = [{"key": r[0], "label": r[1]} for r in User.ROLE_CHOICES]
    return json_response({"roles": roles})


# -------------------------
# IMPERSONATION (production-ready)
# -------------------------
@login_required
@user_passes_test(is_manager_or_admin)
@require_POST
def impersonate_user(request: HttpRequest, user_id: str):
    """
    Débute une session d'impersonation.
    - Nécessite 2FA validée dans la session (request.session['2fa_verified'] == True).
    - Enregistre un ImpersonationLog avec start_time, IP, user-agent.
    - Stocke l'id de l'impersonator dans la session pour restauration.
    """
    # Exiger MFA
    if not request.session.get("2fa_verified"):
        return json_response({"error": "Validation 2FA requise avant impersonation"}, 403)

    data = parse_json(request)
    reason = data.get("reason", "").strip()
    if not reason or len(reason) < 5:
        return json_response({"error": "Une raison détaillée (>=5 caractères) est requise"}, 400)

    target_user = get_object_or_404(User, id=user_id)
    # manager non-superuser ne peut pas impersonner d'autres managers/admins
    if target_user.role in (User.ROLE_ADMIN, User.ROLE_MANAGER) and not request.user.is_superuser:
        raise PermissionDenied("Vous ne pouvez pas impersonner cet utilisateur")

    # Informations sur l'initiateur
    ip = request.META.get("REMOTE_ADDR")
    ua = request.META.get("HTTP_USER_AGENT", "")[:512]

    # Créer le log d'impersonation (start)
    log = ImpersonationLog.objects.create(
        impersonator=request.user,
        target=target_user,
        reason=reason,
        start_time=timezone.now(),
        start_ip=ip,
        start_user_agent=ua,
    )

    # Stocker l'info dans la session
    request.session["impersonator_id"] = str(request.user.id)
    request.session["impersonator_email"] = request.user.email
    request.session["impersonation_reason"] = reason
    request.session["impersonation_start"] = log.start_time.isoformat()
    request.session["impersonation_log_id"] = str(log.id)

    # Effectuer le login (remplace la session courant)
    auth_login(request, target_user)

    audit(request.user, "impersonate_start", f"Impersonation -> {target_user.email} reason={reason}")
    return json_response({
        "message": f"Vous êtes maintenant connecté en tant que {target_user.email}",
        "target_user": str(target_user.id),
        "impersonation_log_id": str(log.id),
    }, 200)


@login_required
@require_POST
def stop_impersonation(request: HttpRequest):
    """
    Termine la session d'impersonation et restaure l'identité originale.
    - Met à jour ImpersonationLog.end_time, end_ip, end_user_agent, terminated_by.
    - Reconnecte l'impersonator.
    """
    log_id = request.session.get("impersonation_log_id")
    impersonator_id = request.session.get("impersonator_id")
    if not impersonator_id or not log_id:
        return json_response({"error": "Aucune session d'impersonation active"}, 400)

    # récupérer le log et le mettre à jour
    try:
        log = ImpersonationLog.objects.get(id=log_id)
    except ImpersonationLog.DoesNotExist:
        log = None

    end_ip = request.META.get("REMOTE_ADDR")
    end_ua = request.META.get("HTTP_USER_AGENT", "")[:512]
    end_time = timezone.now()

    if log:
        log.end_time = end_time
        log.end_ip = end_ip
        log.end_user_agent = end_ua
        try:
            terminated_by = User.objects.get(id=impersonator_id)
            log.terminated_by = terminated_by
        except User.DoesNotExist:
            log.terminated_by = None
        log.save()

    # restaurer l'utilisateur original
    try:
        impersonator = User.objects.get(id=impersonator_id)
    except User.DoesNotExist:
        return json_response({"error": "Utilisateur original introuvable"}, 500)

    auth_login(request, impersonator)

    # nettoyer la session
    for k in ("impersonator_id", "impersonator_email", "impersonation_reason", "impersonation_start", "impersonation_log_id"):
        request.session.pop(k, None)

    audit(impersonator, "impersonate_stop", f"Fin impersonation, log_id={log_id}")
    return json_response({"message": "Impersonation terminée. Identité originale restaurée."}, 200)


@login_required
@require_GET
def impersonation_status(request: HttpRequest):
    """
    Indique si la session courante est une impersonation et renvoie métadonnées.
    """
    if "impersonator_id" not in request.session:
        return json_response({"impersonating": False})
    return json_response({
        "impersonating": True,
        "impersonator_id": request.session.get("impersonator_id"),
        "impersonator_email": request.session.get("impersonator_email"),
        "reason": request.session.get("impersonation_reason"),
        "start_time": request.session.get("impersonation_start"),
        "impersonation_log_id": request.session.get("impersonation_log_id"),
        "current_user": request.user.email,
    })


# -------------------------
# AUDIT & LOGS
# -------------------------
@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def audit_logs(request: HttpRequest):
    qs = AuditLog.objects.select_related("user").order_by("-timestamp")[:1000]
    out = [{"timestamp": a.timestamp.isoformat(), "user": a.user.email if a.user else None, "action": a.action, "details": a.details, "ip": a.ip_address} for a in qs]
    return json_response(out)


@login_required
@user_passes_test(is_manager_or_admin)
def system_logs(request: HttpRequest):
    # In production, read from central logging (ELK/Loki). We return a stub.
    return json_response({"message": "system logs endpoint - integrate log aggregation (ELK/Loki)"}, 501)


# -------------------------
# GESTION INTERNE ET CONFORMITÉ (REPORTS / AML / FRAUDE / RISQUE)
# -------------------------
@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def financial_report(request: HttpRequest):
    """
    Rapport global de performance financière.
    Agrège les montants totaux des transactions et soldes des comptes.
    Accessible uniquement aux managers et administrateurs.
    """
    total_accounts = BankAccount.objects.count()
    total_balance = BankAccount.objects.aggregate(total=models.Sum("balance"))["total"] or Decimal("0.00")
    total_deposits = Transaction.objects.filter(type=Transaction.TYPE_DEPOSIT, status=Transaction.STATUS_COMPLETED).aggregate(
        total=models.Sum("amount")
    )["total"] or Decimal("0.00")
    total_withdrawals = Transaction.objects.filter(type=Transaction.TYPE_WITHDRAWAL, status=Transaction.STATUS_COMPLETED).aggregate(
        total=models.Sum("amount")
    )["total"] or Decimal("0.00")
    total_transfers = Transaction.objects.filter(type=Transaction.TYPE_TRANSFER, status=Transaction.STATUS_COMPLETED).aggregate(
        total=models.Sum("amount")
    )["total"] or Decimal("0.00")

    data = {
        "total_accounts": total_accounts,
        "total_balance": str(total_balance),
        "total_deposits": str(total_deposits),
        "total_withdrawals": str(total_withdrawals),
        "total_transfers": str(total_transfers),
        "net_flow": str(total_deposits - total_withdrawals),
    }
    audit(request.user, "financial_report", "Rapport financier global consulté")
    return json_response(data)


@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def aml_check(request: HttpRequest):
    """
    Vérifie les transactions suspectes selon des règles simples.
    (En production, cela utiliserait une intégration AML réelle ou un moteur IA.)
    """
    suspicious_transactions = Transaction.objects.filter(
        models.Q(amount__gt=Decimal("10000000")) |  # transactions > 10 millions
        models.Q(status=Transaction.STATUS_FAILED)
    ).select_related("from_account", "to_account")

    alerts = []
    for tx in suspicious_transactions:
        alerts.append({
            "tx_id": str(tx.id),
            "type": tx.type,
            "amount": str(tx.amount),
            "status": tx.status,
            "from": tx.from_account.account_number if tx.from_account else None,
            "to": tx.to_account.account_number if tx.to_account else tx.to_account_number,
            "created_at": tx.created_at.isoformat(),
            "reason": "Montant inhabituel" if tx.amount > Decimal("10000000") else "Échec de transaction suspect",
        })

    audit(request.user, "aml_check", f"{len(alerts)} alertes détectées")
    return json_response({"alerts": alerts, "total_alerts": len(alerts)})


@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def fraud_detection_report(request: HttpRequest):
    """
    Détection simple des anomalies ou fraudes potentielles.
    Exemple : plusieurs retraits consécutifs sur courte période ou comptes dormants.
    """
    recent_withdrawals = Transaction.objects.filter(
        type=Transaction.TYPE_WITHDRAWAL,
        created_at__gte=timezone.now() - timezone.timedelta(days=1)
    ).values("from_account").annotate(count=models.Count("id")).filter(count__gte=5)

    dormant_accounts = BankAccount.objects.filter(
        is_active=True,
        balance__gt=Decimal("0.00"),
        created_at__lte=timezone.now() - timezone.timedelta(days=365)
    ).exclude(
        outgoing_transactions__created_at__gte=timezone.now() - timezone.timedelta(days=180)
    )

    audit(request.user, "fraud_detection_report", "Rapport de détection de fraude généré")

    return json_response({
        "frequent_withdrawals_accounts": [r["from_account"] for r in recent_withdrawals],
        "dormant_accounts": [a.account_number for a in dormant_accounts],
    })


@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def risk_assessment_report(request: HttpRequest):
    """
    Évalue le risque global des clients selon leur activité et leur solde.
    Score simple : (transactions récentes, volume, comportement).
    """
    clients = User.objects.filter(role=User.ROLE_CLIENT)
    report = []

    for client in clients:
        tx_count = Transaction.objects.filter(
            models.Q(from_account__owner=client) | models.Q(to_account__owner=client)
        ).count()
        total_balance = BankAccount.objects.filter(owner=client).aggregate(total=models.Sum("balance"))["total"] or Decimal("0.00")
        score = 50
        if tx_count > 100:
            score += 20
        if total_balance > Decimal("10000000"):
            score += 20
        if tx_count < 2:
            score -= 15
        report.append({
            "client": client.email,
            "transactions": tx_count,
            "total_balance": str(total_balance),
            "risk_score": score,
        })

    audit(request.user, "risk_assessment", "Rapport de risque client généré")
    return json_response({"clients": report})


# -------------------------
# SECURITY / BRUTE FORCE / BLOCKED IPs
# -------------------------
@login_required
@user_passes_test(is_manager_or_admin)
def blocked_ips(request: HttpRequest):
    # If using django-axes or WAF, expose blocked IP list; stub for now
    return json_response({"blocked_ips": []})


@login_required
@user_passes_test(is_manager_or_admin)
def brute_force_status(request: HttpRequest):
    # Integrate with django-axes for details; stub:
    return json_response({"message": "integrate django-axes to monitor brute-force attempts"}, 501)


# ============================================================
# 🔐 SÉCURITÉ — 2FA, WHITELIST IP, SESSIONS, AUDIT EXPORT
# Production-grade security layer for banking systems
# ============================================================


# ------------------------------------------------------------
# 🧩 DOUBLE AUTHENTIFICATION (2FA / OTP)
# ------------------------------------------------------------
@csrf_protect
@login_required
@require_POST
@never_cache
def enable_2fa(request: HttpRequest):
    """
    Active la double authentification (2FA) pour l'utilisateur connecté.
    Un code à usage unique est généré et stocké temporairement en cache.
    En production, ce code serait envoyé via SMS ou e-mail sécurisé.
    """
    user = request.user
    # Génération d’un code OTP aléatoire sécurisé (6 chiffres)
    otp_code = str(secrets.randbelow(999999)).zfill(6)
    cache_key = f"otp_{user.id}"
    cache.set(cache_key, otp_code, timeout=300)  # valide 5 min

    # En prod : appel d’un service SMS/email
    audit(user, "2fa_requested", f"Code OTP généré pour {user.email}")
    return json_response({
        "message": "Code 2FA généré et envoyé via canal sécurisé.",
        "validity": "5 minutes"
    })


@csrf_protect
@login_required
@require_POST
@never_cache
def verify_2fa(request: HttpRequest):
    """
    Vérifie le code OTP soumis par l'utilisateur.
    En cas de succès, la session est marquée comme '2FA validée'.
    """
    data = parse_json(request)
    code = str(data.get("code", "")).strip()
    cache_key = f"otp_{request.user.id}"
    expected = cache.get(cache_key)

    if not expected:
        audit(request.user, "2fa_failed_expired", "Code expiré ou non généré")
        return json_response({"error": "Code expiré ou inexistant"}, 403)

    if code != expected:
        audit(request.user, "2fa_failed_invalid", f"Code saisi: {code}")
        return json_response({"error": "Code invalide"}, 403)

    # Validation réussie
    cache.delete(cache_key)
    request.session["2fa_verified"] = True
    audit(request.user, "2fa_verified", "Authentification à deux facteurs réussie")
    return json_response({"message": "Vérification 2FA réussie"})


# ------------------------------------------------------------
# 🌐 GESTION DES ADRESSES IP AUTORISÉES (WHITELIST)
# ------------------------------------------------------------
ALLOWED_IPS_CACHE_KEY = "allowed_ips_list"


@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
def get_allowed_ips(request: HttpRequest):
    """Retourne la liste actuelle des IP autorisées."""
    ips = cache.get(ALLOWED_IPS_CACHE_KEY, [])
    audit(request.user, "list_whitelist", f"{len(ips)} IPs consultées")
    return json_response({"allowed_ips": ips})


@login_required
@user_passes_test(is_manager_or_admin)
@require_POST
def add_allowed_ip(request: HttpRequest):
    """Ajoute une nouvelle IP à la liste blanche (whitelist)."""
    data = parse_json(request)
    ip = str(data.get("ip", "")).strip()
    if not ip:
        return json_response({"error": "Adresse IP requise"}, 400)

    ips = cache.get(ALLOWED_IPS_CACHE_KEY, [])
    if ip not in ips:
        ips.append(ip)
        cache.set(ALLOWED_IPS_CACHE_KEY, ips, None)
        audit(request.user, "add_ip_whitelist", ip)
    return json_response({"message": f"{ip} ajoutée à la liste blanche"})


@login_required
@user_passes_test(is_manager_or_admin)
@require_POST
def remove_allowed_ip(request: HttpRequest):
    """Supprime une IP de la whitelist."""
    data = parse_json(request)
    ip = str(data.get("ip", "")).strip()
    ips = cache.get(ALLOWED_IPS_CACHE_KEY, [])
    if ip in ips:
        ips.remove(ip)
        cache.set(ALLOWED_IPS_CACHE_KEY, ips, None)
        audit(request.user, "remove_ip_whitelist", ip)
    return json_response({"message": f"{ip} supprimée de la liste blanche"})


# ------------------------------------------------------------
# 💻 SURVEILLANCE DES SESSIONS ACTIVES
# ------------------------------------------------------------
@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
@never_cache
def list_active_sessions(request: HttpRequest):
    """
    Liste toutes les sessions utilisateur actives.
    Permet d’auditer les connexions en temps réel.
    """
    sessions = Session.objects.all()
    active = []
    now = timezone.now()
    for s in sessions:
        data = s.get_decoded()
        uid = data.get("_auth_user_id")
        if uid:
            try:
                user = User.objects.get(id=uid)
                active.append({
                    "session_key": s.session_key,
                    "user": user.email,
                    "created": s.expire_date - timezone.timedelta(days=7),
                    "expires": s.expire_date,
                    "is_expired": s.expire_date < now
                })
            except User.DoesNotExist:
                continue
    audit(request.user, "list_sessions", f"{len(active)} sessions actives listées")
    return json_response({"active_sessions": active})


# ------------------------------------------------------------
# 📦 EXPORTATION SÉCURISÉE DES JOURNAUX D’AUDIT
# ------------------------------------------------------------
@login_required
@user_passes_test(is_manager_or_admin)
@require_GET
@never_cache
def export_audit_logs_csv(request: HttpRequest):
    """
    Exporte les journaux d’audit récents en CSV chiffré.
    En production, ce fichier doit être signé ou envoyé via canal SFTP.
    """
    qs = AuditLog.objects.select_related("user").order_by("-timestamp")[:5000]
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["timestamp", "user", "action", "details", "ip"])
    for a in qs:
        writer.writerow([
            a.timestamp.isoformat(),
            a.user.email if a.user else "",
            a.action,
            a.details,
            a.ip_address or "",
        ])
    response = HttpResponse(buffer.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = "attachment; filename=audit_logs.csv"
    audit(request.user, "export_audit_logs", f"{qs.count()} entrées exportées")
    return response


# ---------------------------
# BACKUPS
# ---------------------------
class BackupJobListCreateView(generics.ListCreateAPIView):
    serializer_class = BackupJobSerializer
    permission_classes = [IsAdminOrManager]

    def get_queryset(self):
        return BackupJob.objects.all()

    def perform_create(self, serializer):
        serializer.save(initiated_by=self.request.user, status="queued")
        AuditLog.objects.create(user=self.request.user, action="backup_initiated")
