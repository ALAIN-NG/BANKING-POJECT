# backend/banking/signals.py
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
import logging

# Configuration du logger
logger = logging.getLogger(__name__)

# Note: importer les modèles à l'intérieur des handlers pour éviter
# les problèmes d'import circulaire au démarrage.
# Les handlers doivent rester simples et idempotents.


@receiver(post_save, dispatch_uid="banking.transaction_post_save")
def transaction_post_save(sender, instance, created, **kwargs):
    """
    Quand une Transaction est créée ou mise à jour, on écrit un AuditLog.
    - created == True -> transaction nouvellement créée
    - created == False -> update (p.ex. changement de status => loger)
    """
    # Eviter d'agir sur d'autres modèles portant le même nom
    from .models import Transaction, AuditLog

    if sender is not Transaction:
        return

    # Compose un message succinct
    if created:
        action = "transaction_created"
        details = (f"Tx {instance.id} created: {instance.type} "
                   f"{instance.amount} to {instance.to_account_number}")
    else:
        # log change of status if completed/failed
        action = "transaction_updated"
        details = f"Tx {instance.id} status={instance.status}"

    # Tentative d'insertion auditable
    try:
        AuditLog.objects.create(
            user=getattr(instance, "created_by", None),
            action=action,
            details=details,
            timestamp=getattr(instance, "completed_at", timezone.now()),
        )
    except Exception as e:
        # Logger l'erreur au lieu de passer silencieusement
        logger.error(f"Failed to create audit log for transaction: {e}")
        # Ne pas faire échouer tout le pipeline si log échoue


@receiver(post_save, dispatch_uid="banking.bankaccount_post_save")
def bankaccount_post_save(sender, instance, created, **kwargs):
    """
    Quand un BankAccount est créé, log pour l'audit.
    """
    from .models import BankAccount, AuditLog

    if sender is not BankAccount:
        return

    if created:
        try:
            AuditLog.objects.create(
                user=getattr(instance, "owner", None),
                action="account_created",
                details=(f"Account {instance.account_number} created "
                         f"for {instance.owner}"),
            )
        except Exception as e:
            logger.error(f"Failed to create audit log for bank account: {e}")


@receiver(post_delete, dispatch_uid="banking.transaction_post_delete")
def transaction_post_delete(sender, instance, **kwargs):
    """
    Quand une Transaction est supprimée, on enregistre un AuditLog.
    (dans un système bancaire réel on éviterait la suppression physique
    des transactions et privilégierait le flag 'deleted' ou archival)
    """
    from .models import Transaction, AuditLog

    if sender is not Transaction:
        return

    try:
        AuditLog.objects.create(
            user=getattr(instance, "created_by", None),
            action="transaction_deleted",
            details=f"Tx {instance.id} deleted",
        )
    except Exception as e:
        logger.error(f"Failed to create audit log for transaction delete: {e}")
