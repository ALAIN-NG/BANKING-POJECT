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
    path("loans/", views.LoanListCreateView.as_view(), name="loan-list-create"),
    path("loans/<uuid:pk>/approve/", views.LoanApproveView.as_view(), name="loan-approve"),
    path("loans/<uuid:pk>/payment/", views.LoanPaymentView.as_view(), name="loan-payment"),

    # -------------------------
    # NOTIFICATIONS
    # -------------------------
    path("notifications/", views.NotificationListView.as_view(), name="notification-list"),
    path("notifications/<uuid:pk>/read/", views.NotificationReadView.as_view(), name="notification-read"),

    # -------------------------
    # RAPPORTS / AML / Fraud / Risk
    # -------------------------
    path("reports/financial/", views.financial_report, name="financial_report"),
    path("reports/aml-check/", views.aml_check, name="aml_check"),
    path("reports/fraud-detection/", views.fraud_detection_report, name="fraud_detection_report"),
    path("reports/risk-assessment/", views.risk_assessment_report, name="risk_assessment_report"),

    # -------------------------
    # EMPLOYÉS / ADMIN
    # -------------------------
    path("employees/", views.list_employees_detailed, name="list_employees_detailed"),
    path("employees/create/", views.create_employee, name="create_employee"),
    path("admin/users/<uuid:user_id>/toggle/", views.toggle_user_active, name="toggle_user_active"),
    path("employees/<uuid:user_id>/", views.get_employee_detail, name="get_employee_detail"),
    path("employees/<uuid:user_id>/update-profile/", views.update_employee_profile, name="update_employee_profile"),
    path("employees/<uuid:user_id>/set-role/", views.set_user_role, name="set_user_role"),
    path("employees/<uuid:user_id>/reset-password/", views.reset_user_password, name="reset_user_password"),
    path("employees/<uuid:user_id>/force-logout/", views.force_logout_user, name="force_logout_user"),
    path("employees/<uuid:user_id>/audit/", views.get_employee_audit, name="get_employee_audit"),
    path("roles/", views.list_roles, name="list_roles"),

    # -------------------------
    # JOURNAUX / AUDIT / BACKUP
    # -------------------------
    path("admin/audit/", views.audit_logs, name="audit_logs"),
    path("admin/system-logs/", views.system_logs, name="system_logs"),
    # path("admin/backup/", views.trigger_backup.as_view(), name="trigger_backup"),

    # -------------------------
    # SÉCURITÉ AVANCÉE
    # -------------------------
    path("security/blocked-ips/", views.blocked_ips, name="blocked_ips"),
    path("security/bruteforce/", views.brute_force_status, name="brute_force_status"),
    path("security/2fa/enable/", views.enable_2fa, name="enable_2fa"),
    path("security/2fa/verify/", views.verify_2fa, name="verify_2fa"),
    path("security/whitelist/", views.get_allowed_ips, name="get_allowed_ips"),
    path("security/whitelist/add/", views.add_allowed_ip, name="add_allowed_ip"),
    path("security/whitelist/remove/", views.remove_allowed_ip, name="remove_allowed_ip"),
    path("security/sessions/", views.list_active_sessions, name="list_active_sessions"),
    path("security/audit/export/", views.export_audit_logs_csv, name="export_audit_logs_csv"),

    # --------------------------
    # IMPERSONATION
    # --------------------------
    path("employees/<uuid:user_id>/impersonate/", views.impersonate_user, name="impersonate_user"),
    path("employees/impersonation/stop/", views.stop_impersonation, name="stop_impersonation"),
    path("employees/impersonation/status/", views.impersonation_status, name="impersonation_status"),


]
