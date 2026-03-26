from django.apps import AppConfig
from django.core.management import get_commands


class DjangoBizPortalClientConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_bizportal_client'
    verbose_name = 'BizPortal Client'

    def ready(self):
        # Force this app's createsuperuser command to win regardless of INSTALLED_APPS order.
        get_commands()['createsuperuser'] = self.name
