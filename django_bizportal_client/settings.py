from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


DEFAULTS = {
    'OIDC_SCOPE': 'openid email',
    'OIDC_STATE_MAX_AGE_SECONDS': 300,
    'OIDC_TIMEOUT_SECONDS': 10,
    'OIDC_IDENTITY_MODEL': 'django_bizportal_client.OIDCIdentity',
    'OIDC_AUTH_BACKEND': 'django_bizportal_client.backends.BizPortalOIDCBackend',
    'OIDC_AUTO_LINK_BY_EMAIL': False,
    'OIDC_AUTO_CREATE_USER': False,
}


def get_setting(setting_name, default=None):
    if hasattr(settings, setting_name):
        return getattr(settings, setting_name)
    if default is not None:
        return default
    if setting_name in DEFAULTS:
        return DEFAULTS[setting_name]
    raise ImproperlyConfigured(f'{setting_name} must be configured in settings.')


def get_required_setting(setting_name):
    value = get_setting(setting_name, '')
    if isinstance(value, str):
        value = value.strip()
    if value:
        return value
    raise ImproperlyConfigured(f'{setting_name} must be configured in settings.')


def get_oidc_identity_model():
    model_path = get_setting('OIDC_IDENTITY_MODEL', DEFAULTS['OIDC_IDENTITY_MODEL'])
    if not model_path or '.' not in model_path:
        raise ImproperlyConfigured('OIDC_IDENTITY_MODEL must be in the format "app_label.ModelName".')
    app_label, model_name = model_path.split('.', 1)
    return apps.get_model(app_label, model_name)
