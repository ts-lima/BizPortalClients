from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.db import transaction
from django.utils import timezone

from .settings import get_setting, get_oidc_identity_model

USERNAME_MAX_LENGTH = 150
USERNAME_SUFFIX_RESERVED = 10
USERNAME_PREFIX_MAX_LENGTH = USERNAME_MAX_LENGTH - USERNAME_SUFFIX_RESERVED


class BizPortalOIDCBackend(BaseBackend):
    def authenticate(self, request, user=None, oidc_claims=None, oidc_userinfo=None, oidc_issuer=None, **kwargs):
        if user is not None:
            return user
        if not oidc_claims or not oidc_userinfo or not oidc_issuer:
            return None

        OIDCIdentity = get_oidc_identity_model()
        if OIDCIdentity is None:
            return None

        sub = (oidc_userinfo.get('sub') or oidc_claims.get('sub') or '').strip()
        if not sub:
            return None

        identity = OIDCIdentity.objects.filter(
            issuer=oidc_issuer,
            subject=sub,
        ).select_related('user').first()
        if identity:
            self._update_identity(identity, oidc_claims, oidc_userinfo)
            self._update_user_profile(identity.user, oidc_claims, oidc_userinfo)
            return identity.user

        email = (oidc_userinfo.get('email') or oidc_claims.get('email') or '').strip()
        if get_setting('OIDC_AUTO_LINK_BY_EMAIL') and email:
            user_model = get_user_model()
            linked_user = user_model._default_manager.filter(email__iexact=email).first()
            if linked_user:
                identity = OIDCIdentity.objects.create(user=linked_user, issuer=oidc_issuer, subject=sub)
                self._update_identity(identity, oidc_claims, oidc_userinfo)
                self._update_user_profile(linked_user, oidc_claims, oidc_userinfo)
                return linked_user

        if not get_setting('OIDC_AUTO_CREATE_USER'):
            return None

        with transaction.atomic():
            new_user = self._create_user(oidc_claims, oidc_userinfo, sub)
            identity = OIDCIdentity.objects.create(user=new_user, issuer=oidc_issuer, subject=sub)
            self._update_identity(identity, oidc_claims, oidc_userinfo)
        return new_user

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User._default_manager.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _update_user_profile(self, user, oidc_claims, oidc_userinfo):
        email = (oidc_userinfo.get('email') or oidc_claims.get('email') or '').strip()
        full_name = (oidc_userinfo.get('name') or oidc_claims.get('name') or '').strip()

        updated = []
        if email and user.email != email:
            user.email = email
            updated.append('email')

        if full_name:
            first_name, _, last_name = full_name.partition(' ')
            if first_name and user.first_name != first_name:
                user.first_name = first_name
                updated.append('first_name')
            if last_name and user.last_name != last_name:
                user.last_name = last_name
                updated.append('last_name')

        if updated:
            user.save(update_fields=updated)

    def _create_user(self, oidc_claims, oidc_userinfo, sub):
        User = get_user_model()
        email = (oidc_userinfo.get('email') or oidc_claims.get('email') or '').strip()
        preferred_username = (
            oidc_userinfo.get('preferred_username')
            or oidc_claims.get('preferred_username')
            or (email.split('@')[0] if email else '')
            or f'oidc-{sub[:USERNAME_PREFIX_MAX_LENGTH - 5]}'
        )
        username = preferred_username[:USERNAME_MAX_LENGTH] or f'oidc-{sub[:USERNAME_PREFIX_MAX_LENGTH - 5]}'
        original = username

        existing_usernames = set(
            User._default_manager.filter(
                username__startswith=original[:USERNAME_PREFIX_MAX_LENGTH]
            ).values_list('username', flat=True)
        )
        if username in existing_usernames:
            counter = 1
            while True:
                suffix = f'-{counter}'
                username = f'{original[:USERNAME_MAX_LENGTH - len(suffix)]}{suffix}'
                if username not in existing_usernames:
                    break
                counter += 1

        full_name = (oidc_userinfo.get('name') or oidc_claims.get('name') or '').strip()
        first_name, _, last_name = full_name.partition(' ')

        return User._default_manager.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

    def _update_identity(self, identity, oidc_claims, oidc_userinfo):
        company_slug = (oidc_userinfo.get('company_slug') or oidc_claims.get('company_slug') or '').strip()
        identity.company_slug = company_slug
        identity.last_login_at = timezone.now()
        identity.save(update_fields=['company_slug', 'last_login_at'])
