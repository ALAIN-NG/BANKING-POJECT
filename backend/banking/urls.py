# backend/banking/urls.py
from django.urls import path
from . import views

app_name = "banking"

urlpatterns = [
    # -------------------------
    # AUTHENTIFICATION & SÉCURITÉ
    # -------------------------
    path("auth/register/", views.register, name="register"),
    path("auth/login/", views.login_view, name="login"),
    path("auth/logout/", views.logout_view, name="logout"),
    path("auth/change-password/", views.change_password, name="change_password"),
    path("auth/request-reset/", views.request_password_reset, name="request_reset"),
    path("auth/verify/", views.verify_email_or_2fa, name="verify"),

    # -------------------------
    # CLIENTS
    # -------------------------
    path("clients/", views.list_clients, name="list_clients"),
    path("clients/create/", views.create_client, name="create_client"),
    path("clients/<uuid:user_id>/disable/", views.disable_client, name="disable_client"),
    path("clients/<uuid:user_id>/kyc-upload/", views.kyc_upload, name="kyc_upload"),

    # -------------------------
    # COMPTES BANCAIRES
    # -------------------------
    path("accounts/", views.list_accounts, name="list_accounts"),
    path("accounts/create/", views.create_account, name="create_account"),
    path("accounts/<str:account_number>/", views.account_detail, name="account_detail"),
    path("accounts/<str:account_number>/toggle/", views.toggle_account, name="toggle_account"),
    path("accounts/<str:account_number>/close/", views.close_account, name="close_account"),
    path("accounts/<str:account_number>/statement/", views.account_statement, name="account_statement"),

    # -------------------------
    # TRANSACTIONS
    # -------------------------
    path("transactions/deposit/", views.deposit, name="deposit"),
    path("transactions/withdraw/", views.withdraw, name="withdraw"),
    path("transactions/transfer/", views.transfer, name="transfer"),
    path("transactions/external/", views.external_transfer, name="external_transfer"),
    path("transactions/", views.list_transactions, name="list_transactions"),
    path("transactions/<uuid:tx_id>/cancel/", views.cancel_transaction, name="cancel_transaction"),
    path("transactions/export/csv/", views.export_transactions_csv, name="export_transactions_csv"),

    # -------------------------
    # CARTES BANCAIRES
    # -------------------------
    path("cards/create/", views.create_card, name="create_card"),
    path("cards/", views.list_cards, name="list_cards"),
    path("cards/<uuid:card_id>/block/", views.block_card, name="block_card"),
    path("cards/<uuid:card_id>/renew/", views.renew_card, name="renew_card"),

    # -------------------------
    # PRÊTS
    # -------------------------
    path("loans/", views.list_loans, name="list_loans"),
    path("loans/apply/", views.apply_loan, name="apply_loan"),
    path("loans/<uuid:pk>/approve/", views.approve_loan, name="approve_loan"),
    path("loans/<uuid:pk>/payment/", views.loan_payment, name="loan_payment"),

    # -------------------------
    # NOTIFICATIONS / SUPPORT
    # -------------------------
    path("notifications/", views.list_notifications, name="list_notifications"),
    path("notifications/send/", views.send_notification, name="send_notification"),
    path("notifications/<uuid:pk>/read/", views.mark_notification_read, name="mark_notification_read"),

    # -------------------------
    # RAPPORTS / AML
    # -------------------------
    path("reports/financial/", views.financial_report, name="financial_report"),
    path("reports/aml-check/", views.aml_check, name="aml_check"),

    # -------------------------
    # EMPLOYÉS / ADMIN
    # -------------------------
    path("employees/", views.list_employees, name="list_employees"),
    path("employees/create/", views.create_employee, name="create_employee"),
    path("admin/users/<uuid:user_id>/toggle/", views.toggle_user_active, name="toggle_user_active"),

    # -------------------------
    # JOURNAUX / AUDIT / BACKUP
    # -------------------------
    path("admin/audit/", views.audit_logs, name="audit_logs"),
    path("admin/system-logs/", views.system_logs, name="system_logs"),
    path("admin/backup/", views.trigger_backup, name="trigger_backup"),

    # -------------------------
    # SÉCURITÉ AVANCÉE
    # -------------------------
    path("security/blocked-ips/", views.blocked_ips, name="blocked_ips"),
    path("security/bruteforce/", views.brute_force_status, name="brute_force_status"),
]
