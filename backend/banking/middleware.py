from django.utils import timezone
from django.http import HttpResponseForbidden
from django.conf import settings


class ImpersonationMiddleware:
    """
    Middleware pour :
      - expirer automatiquement une impersonation après IMPERSONATION_MAX_SECONDS
      - empêcher l'exécution d'actions sensibles quand la session est en impersonation
    Doit être placé **après** AuthenticationMiddleware dans MIDDLEWARE.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.max_seconds = getattr(settings, "IMPERSONATION_MAX_SECONDS", 15 * 60)
        self.blocked_prefixes = getattr(settings, "IMPERSONATION_BLOCKED_PATH_PREFIXES", [])

    def __call__(self, request):
        session = request.session
        now = timezone.now()

        # Si pas d'impersonation, rien à faire
        impersonator_id = session.get("impersonator_id")
        if not impersonator_id:
            return self.get_response(request)

        # Vérifier le timeout
        start_iso = session.get("impersonation_start")
        if start_iso:
            try:
                start_time = timezone.datetime.fromisoformat(start_iso)
                if timezone.is_naive(start_time):
                    # assume UTC naive -> make aware
                    start_time = timezone.make_aware(start_time)
            except Exception:
                start_time = None
            if start_time:
                elapsed = (now - start_time).total_seconds()
                if elapsed > self.max_seconds:
                    # Auto-terminate: remove keys and force restore of impersonator identity
                    session.pop("impersonator_id", None)
                    session.pop("impersonator_email", None)
                    session.pop("impersonation_reason", None)
                    session.pop("impersonation_start", None)
                    # note: actual re-login is handled by view stop_impersonation; here we deny access to continue
                    return HttpResponseForbidden("Session d'impersonation expirée. Veuillez restaurer votre identité d'origine.")

        # Bloquer accès à endpoints sensibles pendant impersonation
        path = request.path
        for prefix in self.blocked_prefixes:
            # support simple wildcard '*' at the end
            if prefix.endswith("*"):
                if path.startswith(prefix[:-1]):
                    return HttpResponseForbidden("Action interdite pendant une session d'impersonation.")
            else:
                if path.startswith(prefix):
                    return HttpResponseForbidden("Action interdite pendant une session d'impersonation.")

        return self.get_response(request)
