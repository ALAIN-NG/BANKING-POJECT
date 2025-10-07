"""
Django settings for project (DevSecOps Ready)
---------------------------------------------
Compatible avec :
- Environnement local (.env)
- GitHub Actions (secrets)
- Render / Railway (PostgreSQL)

Auteur : ALAIN DJOMO
"""

from pathlib import Path
import environ

# ────────────────────────────────
# BASE & ENV CONFIG
# ────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent

# Initialise django-environ
env = environ.Env(
    DEBUG=(bool, False)
)

# Charger le fichier .env local si présent
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(env_file)

# ────────────────────────────────
# CONFIGURATION DE BASE
# ────────────────────────────────
SECRET_KEY = env("SECRET_KEY", default="django-insecure-change-me-please")
DEBUG = env("DEBUG", default=False)
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

# ────────────────────────────────
# APPLICATIONS
# ────────────────────────────────
INSTALLED_APPS = [
    # Apps Django
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Apps tierces
    "corsheaders",                        # pour gérer le CORS (API / frontend)
    "whitenoise.runserver_nostatic",      # fichiers statiques en production

    # Apps internes
    "banking",
]

AUTH_USER_MODEL = 'banking.CustomUser'

# ────────────────────────────────
# MIDDLEWARE
# ────────────────────────────────
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # sert les fichiers statiques
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "project.urls"

# ────────────────────────────────
# TEMPLATES
# ────────────────────────────────
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "banking" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "project.wsgi.application"
ASGI_APPLICATION = "project.asgi.application"

# ────────────────────────────────
# BASE DE DONNÉES
# ────────────────────────────────
# Lit automatiquement DATABASE_URL depuis .env ou depuis les variables GitHub/Render
DATABASES = {
    "default": env.db(
        default=f"sqlite: ///{BASE_DIR / 'db.sqlite3'}"
    )
}

# Exemple PostgreSQL dans .env ou GitHub Secrets :
# DATABASE_URL=postgres://user:password@host:5432/dbname

# ────────────────────────────────
# VALIDATION DES MOTS DE PASSE
# ────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ────────────────────────────────
# INTERNATIONALISATION
# ────────────────────────────────
LANGUAGE_CODE = "fr-fr"
TIME_ZONE = "Africa/Douala"
USE_I18N = True
USE_TZ = True

# ────────────────────────────────
# FICHIERS STATIQUES & MÉDIAS
# ────────────────────────────────
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "banking" / "static"]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Optimisation des fichiers statiques avec WhiteNoise
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ────────────────────────────────
# LOGGING (pour CI/CD et sécurité)
# ────────────────────────────────
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
        "file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs/django.log",
            "formatter": "verbose",
        },
    },
    "root": {"handlers": ["console", "file"], "level": "INFO"},
}

# ────────────────────────────────
# SÉCURITÉ (Prod vs Dev)
# ────────────────────────────────
# En prod : DEBUG=0 → active les protections suivantes
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
SECURE_SSL_REDIRECT = not DEBUG

# ────────────────────────────────
# CORS (pour le frontend)
# ────────────────────────────────
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOWED_ORIGINS = env.list(
    "CORS_ALLOWED_ORIGINS",
    default=["http://localhost:3000", "http://127.0.0.1:3000"]
)

# ────────────────────────────────
# DEFAULT PRIMARY KEY
# ────────────────────────────────
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
