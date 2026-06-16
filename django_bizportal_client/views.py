import json
import logging
import secrets
import requests

from urllib.parse import urlencode
from authlib.integrations.base_client.errors import OAuthError
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password
from django.contrib.sessions.models import Session
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core.signing import BadSignature, SignatureExpired

from .client import oidc_config, build_authorize_redirect, validate_id_token, build_oauth_session
from .events import UserEvent
from .models import OIDCIdentity
from .settings import get_required_setting, get_setting, get_oidc_identity_model
from .signals import user_event_received


logger = logging.getLogger(__name__)


def safe_next_path(raw_next):
    if not raw_next:
        return '/'
    if not raw_next.startswith('/'):
        return '/'
    if raw_next.startswith('//'):
        return '/'
    return raw_next


def build_signed_state(*, nonce, next_path='/'):
    from django.core import signing

    payload = {
        'nonce': nonce,
        'next': next_path,
        'jti': secrets.token_urlsafe(8),
    }
    return signing.dumps(payload, salt=get_required_setting('OIDC_STATE_SALT'))


def parse_signed_state(raw_state):
    from django.core import signing

    return signing.loads(
        raw_state,
        salt=get_required_setting('OIDC_STATE_SALT'),
        max_age=int(get_setting('OIDC_STATE_MAX_AGE_SECONDS')),
    )


def _cleanup_company_name(raw_name):
    if not raw_name:
        return ''
    corporate_types = ['株式会社', '有限会社', '合資会社', '合名会社', '合同会社']
    for corp_type in corporate_types:
        if corp_type in raw_name:
            raw_name = raw_name.replace(corp_type, '')
            break
    return raw_name.strip()


def oidc_prepare(request):
    config = oidc_config()
    next_path = safe_next_path(request.GET.get('next', '/'))
    nonce = secrets.token_urlsafe(24)
    signed_state = build_signed_state(nonce=nonce, next_path=next_path)
    return redirect(build_authorize_redirect(config=config, signed_state=signed_state, nonce=nonce))


def oidc_login(request):
    return oidc_prepare(request)


def oidc_callback(request):
    config = oidc_config()

    error = request.GET.get('error')
    if error:
        description = request.GET.get('error_description', '')
        return HttpResponseBadRequest(f'authorization error: {error} {description}')

    code = request.GET.get('code')
    if not code:
        return HttpResponseBadRequest('missing authorization code')

    raw_state = request.GET.get('state')
    if not raw_state:
        return HttpResponseBadRequest('missing state')

    try:
        parsed_state = parse_signed_state(raw_state)
    except (SignatureExpired, BadSignature):
        return HttpResponseBadRequest('invalid or expired state')

    expected_nonce = parsed_state.get('nonce')
    if not expected_nonce:
        return HttpResponseBadRequest('state nonce is required')

    client = build_oauth_session()
    try:
        token = client.fetch_token(
            url=config['token_endpoint'],
            code=code,
            grant_type='authorization_code',
            redirect_uri=get_required_setting('OIDC_CLIENT_CALLBACK_URL'),
            timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
        )
        id_token = token.get('id_token')
        if not id_token:
            return HttpResponseBadRequest('id_token is required')

        claims = validate_id_token(id_token, config, expected_nonce)
        sub = claims.get('sub')
        if not sub:
            return HttpResponseBadRequest('sub claim is required')

        issuer = claims.get('iss') or config['issuer']
        access_token = token.get('access_token')
        if not access_token:
            return HttpResponseBadRequest('access_token is required')

        expires_at = timezone.now().timestamp() + int(token.get('expires_in') or 0)
        request.session['oidc_access_token'] = access_token
        request.session['oidc_refresh_token'] = token.get('refresh_token', '')
        request.session['oidc_access_token_expires_at'] = expires_at
        request.session['oidc_sid'] = claims.get('sid', '')

    except (OAuthError, requests.RequestException, ValueError, KeyError, TypeError) as exc:
        logger.warning('OIDC token exchange failed: %s', exc)
        return HttpResponseBadRequest('oidc token exchange failed')

    userinfo = {}
    try:
        userinfo = client.get(
            config['userinfo_endpoint'],
            timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
        ).json()
    except (requests.RequestException, ValueError, TypeError) as exc:
        logger.warning('Failed to fetch optional userinfo: %s', exc)
        userinfo = {}

    userinfo_sub = userinfo.get("sub")
    if userinfo_sub and userinfo_sub != sub:
        return HttpResponseBadRequest("userinfo sub mismatch")

    user = authenticate(
        request,
        oidc_claims=claims,
        oidc_userinfo=userinfo,
        oidc_issuer=issuer,
    )
    if not user:
        return HttpResponseBadRequest('no matching user account found')

    request.session['oidc_company_slug'] = userinfo.get('company_slug') or ''
    request.session['oidc_company_name'] = _cleanup_company_name(userinfo.get('company_name') or '')
    request.session['oidc_installation_name'] = userinfo.get('installation_name') or ''

    backend_path = get_setting('OIDC_AUTH_BACKEND', 'django.contrib.auth.backends.ModelBackend')
    login(request, user, backend=backend_path)
    return redirect(safe_next_path(parsed_state.get('next') or '/'))


@csrf_exempt
@require_POST
def backchannel_logout(request):
    client_secret = get_required_setting('OIDC_CLIENT_SECRET')
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer ') or not check_password(client_secret, auth_header[7:]):
        return JsonResponse({'error': 'unauthorized'}, status=401)

    try:
        data = json.loads(request.body)
        sub = data.get('sub', '').strip()
        sid = data.get('sid', '').strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({'error': 'invalid request'}, status=400)

    if not sub:
        return JsonResponse({'error': 'sub is required'}, status=400)

    try:
        identity = OIDCIdentity.objects.select_related('user').get(subject=sub)
    except OIDCIdentity.DoesNotExist:
        return JsonResponse({'status': 'ok'})

    user_id = str(identity.user.pk)
    for session in Session.objects.filter(expire_date__gte=timezone.now()):
        decoded = session.get_decoded()
        if decoded.get('_auth_user_id') != user_id:
            continue
        if sid and decoded.get('oidc_sid') != sid:
            continue
        session.delete()

    return JsonResponse({'status': 'ok'})


@csrf_exempt
@require_POST
def backchannel_event(request):
    client_secret = get_required_setting('OIDC_CLIENT_SECRET')
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer ') or not check_password(client_secret, auth_header[7:]):
        return JsonResponse({'error': 'unauthorized'}, status=401)

    try:
        data = json.loads(request.body)
        event = data.get('event', '').strip()
        sub = data.get('sub', '').strip()
        sid = data.get('sid', '').strip()
        event_id = data.get('event_id', '').strip()
        issued_at = data.get('issued_at', '').strip()
        company_slug = data.get('company_slug', '').strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({'error': 'invalid request'}, status=400)

    if not event or not sub or not event_id:
        return JsonResponse({'error': 'missing required fields'}, status=400)

    OIDCIdentityModel = get_oidc_identity_model()
    identity = None
    user = None
    if OIDCIdentityModel is not None:
        identity = OIDCIdentityModel.objects.filter(subject=sub).select_related('user').first()
        if identity is not None:
            user = identity.user

    user_event_received.send(
        sender=backchannel_event,
        event=event,
        sub=sub,
        sid=sid,
        event_id=event_id,
        issued_at=issued_at,
        company_slug=company_slug,
        identity=identity,
        user=user,
    )

    return JsonResponse({'status': 'ok'})


@require_POST
def oidc_logout(request):
    request.session.pop('oidc_access_token', None)
    request.session.pop('oidc_refresh_token', None)
    request.session.pop('oidc_access_token_expires_at', None)
    request.session.pop('oidc_company_slug', None)
    request.session.pop('oidc_company_name', None)
    request.session.pop('oidc_installation_name', None)
    logout(request)
    logout_url = f"{get_required_setting('OIDC_ISSUER_URL')}o/logout/?{urlencode({'client_id': get_required_setting('OIDC_CLIENT_ID'), 'state': secrets.token_urlsafe(8)})}"
    return redirect(logout_url)
