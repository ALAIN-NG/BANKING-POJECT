from django.apps import AppConfig
import logging


class BankingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "banking"

    def ready(self):
        # importer le module signals pour connecter les handlers
        # Doing a local import here prevents import-time side-effects
        try:
            import banking.signals  # noqa: F401
        except Exception as e:
            logging.warning(f"Failed to import signals: {e}")
            # Si un import échoue (p.ex. lors d'un manage.py makemigrations initial),
            # on ignore l'erreur ici pour ne pas casser la commande.
            # Les erreurs réelles d'importation devront être visibles dans les logs.
            pass
