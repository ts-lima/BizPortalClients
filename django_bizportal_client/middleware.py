from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime


class OIDCSessionCleanupMiddleware:
    """
    このミドルウェアは、ユーザーのセッションから期限切れの OIDC トークンをクリーンアップする。
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        self.cleanup_expired_tokens(request)
        response = self.get_response(request)
        return response

    def cleanup_expired_tokens(self, request):
        expires_at = request.session.get('oidc_access_token_expires_at')
        if not expires_at:
            return
        try:
            if timezone.now().timestamp() >= float(expires_at):
                request.session.pop('oidc_access_token', None)
                request.session.pop('oidc_refresh_token', None)
                request.session.pop('oidc_access_token_expires_at', None)
        except (TypeError, ValueError):
            request.session.pop('oidc_access_token', None)
            request.session.pop('oidc_refresh_token', None)
            request.session.pop('oidc_access_token_expires_at', None)


class OIDCSessionRefreshMiddleware:
    """
    このミドルウェアは、ユーザーのセッションを定期的に延長して、アクティブな使用中にタイムアウトを防ぐ。

    任意で `settings.py` に `OIDC_SESSION_REFRESH` として定義する可能な設定項目:
    ```
    OIDC_SESSION_REFRESH = {
        'REFRESH_INTERVAL': 86400,  # 24 hours in seconds
        'SKIP_STAFF_USERS': False,
        'SKIP_SUPERUSER_USERS': True,
        'SKIP_STATIC_AND_MEDIA': True,
        'SKIP_UNAUTHENTICATED_USERS': True,
    }
    ```

    セッションのリフレッシュが成功した後、ミドルウェアは `request` オブジェクトに以下の属性を追加する。
    - `request.oidc_session_refreshed`
    - `request.oidc_session_refreshed_at`
    """

    _REFRESH_INTERVAL = 86400  # 24 hours in seconds
    _SKIP_STAFF_USERS = False
    _SKIP_SUPERUSER_USERS = True
    _SKIP_STATIC_AND_MEDIA = True
    _SKIP_UNAUTHENTICATED_USERS = True

    def __init__(self, get_response):
        SETTINGS = getattr(settings, 'OIDC_SESSION_REFRESH', {})
        self._REFRESH_INTERVAL = SETTINGS.get('REFRESH_INTERVAL', self._REFRESH_INTERVAL)
        self._SKIP_STAFF_USERS = SETTINGS.get('SKIP_STAFF_USERS', self._SKIP_STAFF_USERS)
        self._SKIP_SUPERUSER_USERS = SETTINGS.get('SKIP_SUPERUSER_USERS', self._SKIP_SUPERUSER_USERS)
        self._SKIP_STATIC_AND_MEDIA = SETTINGS.get('SKIP_STATIC_AND_MEDIA', self._SKIP_STATIC_AND_MEDIA)
        self._SKIP_UNAUTHENTICATED_USERS = SETTINGS.get('SKIP_UNAUTHENTICATED_USERS', self._SKIP_UNAUTHENTICATED_USERS)

        self.get_response = get_response
        self.refresh_delta = timedelta(seconds=self._REFRESH_INTERVAL)

    def __call__(self, request):
        if self._should_skip_url(request):
            return self.get_response(request)

        if self._should_skip_user(request):
            return self.get_response(request)

        if self._should_refresh_session(request):
            request.session['oidc_session_refreshed_at'] = timezone.now().isoformat()
            request.session.modified = True
            setattr(request, 'oidc_session_refreshed', True)
            setattr(request, 'oidc_session_refreshed_at', timezone.now())

        return self.get_response(request)

    def _should_skip_url(self, request) -> bool:
        if not self._SKIP_STATIC_AND_MEDIA:
            return False

        path = request.path or ''
        static_url = getattr(settings, 'STATIC_URL', '/static/') or '/static/'
        media_url = getattr(settings, 'MEDIA_URL', None)

        if static_url and static_url != '/' and path.startswith(static_url):
            return True

        if media_url and media_url != '/' and path.startswith(media_url):
            return True

        return False

    def _should_skip_user(self, request) -> bool:
        user = getattr(request, 'user', None)
        if self._SKIP_UNAUTHENTICATED_USERS and not getattr(user, 'is_authenticated', False):
            return True
        if self._SKIP_SUPERUSER_USERS and getattr(user, 'is_superuser', False):
            return True
        if self._SKIP_STAFF_USERS and getattr(user, 'is_staff', False):
            return True
        return False

    def _should_refresh_session(self, request) -> bool:
        last_refresh_raw = request.session.get('oidc_session_refreshed_at')
        if not last_refresh_raw:
            return True

        last_refresh = parse_datetime(last_refresh_raw)
        if last_refresh is None:
            return True

        now = timezone.now()
        return now - last_refresh >= self.refresh_delta
