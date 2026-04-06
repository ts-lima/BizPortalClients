import requests

from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt

from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from .settings import get_setting, get_required_setting, get_oidc_identity_model


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

    claims = jwt.decode(id_token, key_set)
    claims.validate()

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
	def __init__(self, request):
		self.request = request
		self.base_url = get_required_setting('OIDC_ISSUER_URL').rstrip('/')

	def _get_access_token(self):
		access_token = self.request.session.get('oidc_access_token', '')
		expires_at = self.request.session.get('oidc_access_token_expires_at', 0)
		if not access_token or timezone.now().timestamp() >= float(expires_at or 0):
			raise BizPortalApiError('BizPortalセッションの有効期限が切れています。再ログインしてください。', status_code=401)
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
				detail = 'BizPortalセッションの有効期限が切れています。再ログインしてください。'
			elif not detail and response.status_code == 403:
				detail = 'BizPortalで対象Companyのownerまたはadmin権限が必要です。'
			elif not detail and response.status_code == 409:
				detail = '指定したユーザーIDは既に登録されています。'
			elif not detail:
				detail = 'BizPortal API request failed'
			raise BizPortalApiError(detail, status_code=response.status_code)

		self.result = payload
		return payload

	def get_username_availability(self, username):
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

	def provision_user(self, *, username, email, password, name='', surname=''):
		try:
			response = requests.post(
				f'{self.base_url}/api/v1/users/provision/',
				json={
					'username': username,
					'email': email,
					'password': password,
					'name': name,
					'surname': surname,
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

	def update_user(self, *, username, email=None, name=None, surname=None):
		data = {
			'username': username,
		}
		if email is not None:
			data['email'] = email
		if name is not None:
			data['name'] = name
		if surname is not None:
			data['surname'] = surname

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

	def password_reset(self, *, username, email):
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
