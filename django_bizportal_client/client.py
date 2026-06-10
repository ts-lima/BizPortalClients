import logging
import requests

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.requests_client import OAuth2Session
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from enum import StrEnum

from .settings import get_setting, get_required_setting, get_oidc_identity_model


logger = logging.getLogger(__name__)


def oidc_config():
    issuer = get_required_setting('OIDC_ISSUER_URL').rstrip('/')
    try:
        metadata = requests.get(f'{issuer}/o/.well-known/openid-configuration', timeout=5)
        metadata.raise_for_status()
        config = metadata.json()
    except (requests.RequestException, ValueError, KeyError) as exc:
        raise ImproperlyConfigured('OIDC discovery configuration could not be retrieved.') from exc
    return {
        'issuer': config['issuer'],
        'authorization_endpoint': config['authorization_endpoint'],
        'token_endpoint': config['token_endpoint'],
        'userinfo_endpoint': config['userinfo_endpoint'],
        'jwks_uri': config['jwks_uri'],
    }


def build_oauth_session():
    return OAuth2Session(
        client_id=get_required_setting('OIDC_CLIENT_ID'),
        client_secret=get_required_setting('OIDC_CLIENT_SECRET'),
        scope=get_setting('OIDC_SCOPE'),
    )


def build_authorize_redirect(*, config, signed_state, nonce):
    client = build_oauth_session()
    uri, _ = client.create_authorization_url(
        config['authorization_endpoint'],
        redirect_uri=get_required_setting('OIDC_CLIENT_CALLBACK_URL'),
        state=signed_state,
        nonce=nonce,
    )
    return uri


def validate_id_token(id_token, config, expected_nonce=None):
    try:
        jwks = requests.get(
            config['jwks_uri'],
            timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
        )
        jwks.raise_for_status()
        key_set = jwks.json()
    except (requests.RequestException, ValueError) as exc:
        raise ValueError('failed to fetch JWKS') from exc

    token = jwt.decode(id_token, KeySet.import_key_set(key_set))
    claims = token.claims
    JWTClaimsRegistry().validate(claims)

    if claims.get('iss') != config['issuer']:
        raise ValueError('invalid issuer')

    aud = claims.get('aud')
    client_id = get_required_setting('OIDC_CLIENT_ID')
    if isinstance(aud, str):
        aud_ok = aud == client_id
    else:
        aud_ok = client_id in (aud or [])
    if not aud_ok:
        raise ValueError('invalid audience')

    if expected_nonce and claims.get('nonce') != expected_nonce:
        raise ValueError('invalid nonce')

    return claims


class BizPortalApiError(Exception):
	def __init__(self, detail, status_code=500):
		super().__init__(detail)
		self.detail = detail
		self.status_code = status_code


class BizPortalClient:
	class CompanyUserRole(StrEnum):
		OWNER = 'owner'
		ADMIN = 'admin'
		MEMBER = 'member'

	def __init__(self, request):
		self.request = request
		self.base_url = get_required_setting('OIDC_ISSUER_URL').rstrip('/')

	def _clear_token_session(self, clear_refresh_token=False):
		self.request.session.pop('oidc_access_token', None)
		self.request.session.pop('oidc_access_token_expires_at', None)
		if clear_refresh_token:
			self.request.session.pop('oidc_refresh_token', None)
		if hasattr(self.request.session, 'modified'):
			self.request.session.modified = True

	def _store_token_response(self, token):
		access_token = token.get('access_token') or ''
		if not access_token:
			raise BizPortalApiError('BizPortalのトークン更新に失敗しました。', status_code=502)

		expires_at = token.get('expires_at')
		try:
			expires_at = float(expires_at)
		except (TypeError, ValueError):
			try:
				expires_in = int(token.get('expires_in') or 0)
			except (TypeError, ValueError):
				expires_in = 0
			expires_at = timezone.now().timestamp() + max(expires_in, 0)

		self.request.session['oidc_access_token'] = access_token
		if token.get('refresh_token'):
			self.request.session['oidc_refresh_token'] = token['refresh_token']
		self.request.session['oidc_access_token_expires_at'] = expires_at
		if hasattr(self.request.session, 'modified'):
			self.request.session.modified = True
		return access_token

	def _refresh_access_token(self):
		refresh_token = self.request.session.get('oidc_refresh_token', '')
		if not refresh_token:
			self._clear_token_session()
			raise BizPortalApiError('BizPortalセッションの有効期限が切れています。', status_code=401)

		client = build_oauth_session()
		try:
			token = client.refresh_token(
				url=oidc_config()['token_endpoint'],
				refresh_token=refresh_token,
				timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
			)
		except (OAuthError, requests.RequestException, ValueError, KeyError, TypeError) as exc:
			logger.warning('OIDC token refresh failed: %s', exc)
			self._clear_token_session(clear_refresh_token=True)
			raise BizPortalApiError('BizPortalセッションの有効期限が切れています。', status_code=401) from exc

		return self._store_token_response(token)

	def _get_access_token(self):
		access_token = self.request.session.get('oidc_access_token', '')
		expires_at = self.request.session.get('oidc_access_token_expires_at', 0)
		try:
			is_expired = timezone.now().timestamp() >= (float(expires_at or 0) - 30)
		except (TypeError, ValueError):
			is_expired = True

		if access_token and not is_expired:
			return access_token

		access_token = self._refresh_access_token()
		return access_token

	def _build_headers(self):
		return {
			'Authorization': f'Bearer {self._get_access_token()}',
			'Accept': 'application/json',
		}

	def _handle_response(self, response):
		try:
			payload = response.json()
		except ValueError:
			payload = {}

		if response.status_code >= 400:
			detail = payload.get('detail') or ''
			if not detail and response.status_code == 401:
				detail = 'BizPortalセッションの有効期限が切れています。'
			elif not detail and response.status_code == 403:
				detail = 'BizPortalで対象Companyのownerまたはadmin権限が必要です。'
			elif not detail and response.status_code == 409:
				detail = 'BizPortalで指定したユーザーIDは既に登録されています。'
			elif not detail:
				detail = 'BizPortal APIへのリクエストが失敗しました。'
			raise BizPortalApiError(detail, status_code=response.status_code)

		self.result = payload
		return payload

	def get_username_availability(self, username: str):
		try:
			response = requests.get(
				f'{self.base_url}/api/v1/users/username-availability/',
				params={'username': username},
				headers=self._build_headers(),
				timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
			)
		except requests.Timeout as exc:
			raise BizPortalApiError('BizPortal APIへの接続がタイムアウトしました。', status_code=504) from exc
		except requests.RequestException as exc:
			raise BizPortalApiError('BizPortal APIへの接続に失敗しました。', status_code=502) from exc
		return self._handle_response(response)

	def provision_user(self, *, username: str, email: str, password: str, name: str = '', surname: str = '', role: CompanyUserRole = CompanyUserRole.MEMBER):
		try:
			response = requests.post(
				f'{self.base_url}/api/v1/users/provision/',
				json={
					'username': username,
					'email': email,
					'password': password,
					'name': name,
					'surname': surname,
					'role': role,
				},
				headers={
					**self._build_headers(),
					'Content-Type': 'application/json',
				},
				timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
			)
		except requests.Timeout as exc:
			raise BizPortalApiError('BizPortal APIへの接続がタイムアウトしました。', status_code=504) from exc
		except requests.RequestException as exc:
			raise BizPortalApiError('BizPortal APIへの接続に失敗しました。', status_code=502) from exc
		return self._handle_response(response)

	def create_oidc_identity(self, user):
		subject = (self.result.get('sub') or '').strip()
		if not subject:
			raise BizPortalApiError('BizPortalの応答にsubが含まれていません。', status_code=502)

		OIDCIdentity = get_oidc_identity_model()
		issuer = oidc_config()['issuer']
		company_slug = (self.result.get('company_slug') or '').strip()

		return OIDCIdentity.objects.create(
			user=user,
			issuer=issuer,
			subject=subject,
			company_slug=company_slug,
		)

	def update_user(self, *, username: str, email: str = None, name: str = None, surname: str = None, role: CompanyUserRole = None):
		data = {
			'username': username,
		}
		if email is not None:
			data['email'] = email
		if name is not None:
			data['name'] = name
		if surname is not None:
			data['surname'] = surname
		if role is not None:
			data['role'] = role
		try:
			response = requests.post(
				f'{self.base_url}/api/v1/users/update/',
				json=data,
				headers={
					**self._build_headers(),
					'Content-Type': 'application/json',
				},
				timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
			)
		except requests.Timeout as exc:
			raise BizPortalApiError('BizPortal APIへの接続がタイムアウトしました。', status_code=504) from exc
		except requests.RequestException as exc:
			raise BizPortalApiError('BizPortal APIへの接続に失敗しました。', status_code=502) from exc
		return self._handle_response(response)

	def delete_user(self, *, username: str, subject: str):
		try:
			response = requests.post(
				f'{self.base_url}/api/v1/users/delete/',
				json={
					'username': username,
					'sub': subject,
				},
				headers={
					**self._build_headers(),
					'Content-Type': 'application/json',
				},
				timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
			)
		except requests.Timeout as exc:
			raise BizPortalApiError('BizPortal APIへの接続がタイムアウトしました。', status_code=504) from exc
		except requests.RequestException as exc:
			raise BizPortalApiError('BizPortal APIへの接続に失敗しました。', status_code=502) from exc
		return self._handle_response(response)

	def password_reset(self, *, username: str, email: str):
		try:
			response = requests.post(
				f'{self.base_url}/api/v1/users/password-reset/',
				json={
					'username': username,
					'email': email,
				},
				headers={
					**self._build_headers(),
					'Content-Type': 'application/json',
				},
				timeout=get_setting('OIDC_TIMEOUT_SECONDS'),
			)
		except requests.Timeout as exc:
			raise BizPortalApiError('BizPortal APIへの接続がタイムアウトしました。', status_code=504) from exc
		except requests.RequestException as exc:
			raise BizPortalApiError('BizPortal APIへの接続に失敗しました。', status_code=502) from exc
		return self._handle_response(response)
