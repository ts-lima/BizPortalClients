# django-bizportal-client

BizPortal を OIDC IdP として使う Django 5+ 向け最小クライアント連携パッケージです。

## インストール

```bash
pip install git+https://github.com/ts-taisei/BizPortalClients.git@dja-1.3.0#subdirectory=django_bizportal_client
```

## 基準設定

`settings.py` に以下を設定します。

```python
INSTALLED_APPS = [
    # ...
    'django_bizportal_client',
]

MIDDLEWARE = [
    # ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # Django のデフォルト認証ミドルウェア
    'django_bizportal_client.middleware.OIDCSessionCleanupMiddleware',
    'django_bizportal_client.middleware.OIDCSessionRefreshMiddleware',
    # ...
]

TEMPLATES = [
    {
        # ...
        'OPTIONS': {
            'context_processors': [
                # ...
                'django_bizportal_client.context_processors.oidc_portal_branding',
                'django_bizportal_client.context_processors.oidc_session_refresh',
            ],
        },
    },
]

LOGIN_URL = '/login/'

AUTHENTICATION_BACKENDS = [
    'django_bizportal_client.backends.BizPortalOIDCBackend',
    'django.contrib.auth.backends.ModelBackend',
]

OIDC_CLIENT_ID = 'your-bizportal-client-id'
OIDC_CLIENT_SECRET = 'your-bizportal-client-secret'
OIDC_CLIENT_CALLBACK_URL = 'https://your-app.example.com/oidc/callback/'
OIDC_ISSUER_URL = 'https://bizportal.example.com/'
OIDC_STATE_SALT = 'oidc-state-v1'

# 任意設定
OIDC_SCOPE = 'openid email'
OIDC_STATE_MAX_AGE_SECONDS = 300
OIDC_TIMEOUT_SECONDS = 10
OIDC_AUTO_LINK_BY_EMAIL = False
OIDC_AUTO_CREATE_USER = False
OIDC_IDENTITY_MODEL = 'django_bizportal_client.OIDCIdentity'
OIDC_LOGIN_REQUIRED_USER_ATTRS = {'is_active': True}
```
**追加情報**：`OIDC_LOGIN_REQUIRED_USER_ATTRS`について、特定の条件でログインを制限したい場合は、`OIDC_LOGIN_REQUIRED_USER_ATTRS` を設定します。これは、ログインに必要なユーザー属性とその理想値を辞書形式で指定するもので、未充足の場合はログインが拒否されます（HTTP 403）。アプリ側で条件を追加することも可能です。
- 例: OIDC_LOGIN_REQUIRED_USER_ATTRS = {'is_active': True, 'is_permitted': True, 'email_verified': True}

---

`urls.py` に以下を追加します。

```python
from django.urls import include, path

urlpatterns = [
    path('', include('django_bizportal_client.urls')),
    # ...
]
```

---

`base.html` などのベーステンプレートに以下を追加します。

```html
<body>
    {# 既存のコンテンツ #}

    {# セッション延長用の iframe を追加   #}
    {{ oidc_session_refresh_iframe|safe }}
</body>
```

---

`OIDCIdentity` モデルのマイグレーションを実行します。

```bash
python manage.py migrate django_bizportal_client
```

## 提供URL

- `/oidc/prepare/` で PKCE code_verifier 生成、state 生成、セッション保存、BizPortal OIDC authorize へリダイレクト
- `/oidc/callback/` でトークン交換、userinfo 取得、ローカルユーザーへログイン
- `/oidc/login/` から BizPortal OIDC authorize へリダイレクト
- `/oidc/logout/` でローカルセッション破棄 + BizPortal ログアウトへリダイレクト
- `/login/` と `/admin/login/` を補足して `/oidc/login/` へリダイレクト
- `/logout/` と `/admin/logout/` を補足して `/oidc/logout/` へリダイレクト

## クライアント側からの API

`django_bizportal_client.client.BizPortalClient` クラスで以下の機能を提供します。

- `get_username_availability`: BizPortal 上でのユーザー名の利用可能性を確認
- `provision_user`: BizPortal 上でユーザーを作成。`password` 省略時はパスワード再設定フローが起動し、`send_reset_email=False` でメール送信を抑制して `password_reset_url` のみ受け取れる。`display_company_name` を指定するとパスワード再設定ページに表示される会社名を上書きできる
- `create_oidc_identity`: クライアント側で OIDCIdentity レコードを作成
- `update_user`: BizPortal 上のユーザー情報を更新 (メールアドレス、名前、苗字、役割、有効状態)。`is_active=False` で当該アプリのアクセスを無効化（InstallationAccess があればそれを、なければ CompanyUser を更新）、`True` で再有効化
- `delete_user`: BizPortal 上のユーザーを削除 (ユーザー名と OIDC subject を指定)
- `password_reset`: BizPortal 上のユーザーのパスワード再設定 URL を生成し、レスポンスの `password_reset_url` で受け取る。`send_reset_email=False` でメール送信を抑制し、クライアント側で URL を管理できる。`display_company_name` を指定するとパスワード再設定ページに表示される会社名を上書きできる。
- `send_email`: BizPortal 上のユーザーの登録メールアドレス宛に任意のメール（件名・本文）を送信する。
- `password_update`: BizPortal 上のユーザーパスワードを Django エンコード済みハッシュで直接更新 (ユーザー名、OIDC subject、password_hash を指定。pbkdf2_sha256 のみ対応)
- `username_update`: BizPortal 上のユーザーIDを変更 (現在のユーザー名、OIDC subject、new_username を指定。`InstallationAccess` による制限モードが有効な導入でのみ利用可能)

### クライアントコードの例

```python
from django_bizportal_client.client import BizPortalClient, BizPortalApiError
from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import HttpResponse

def create_view(request):
    new_username = request.POST.get('username')
    new_email = request.POST.get('email')
    new_password = request.POST.get('password')
    new_name = request.POST.get('name')
    new_surname = request.POST.get('surname')
    new_role = request.POST.get('role')

    # BizPortal クライアントの初期化
    try:
        client = BizPortalClient(request)
    except BizPortalApiError as e:
        raise Exception(f"BizPortal クライアントの初期化に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"BizPortal クライアントの初期化中に予期しないエラー: {str(e)}")

    # ユーザー名の利用可能性を確認
    try:
        response = client.get_username_availability(new_username)
    except BizPortalApiError as e:
        raise Exception(f"ユーザー名の利用可能性の確認に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"ユーザー名の利用可能性の確認中に予期しないエラー: {str(e)}")

    if not response.get('available'):
        raise Exception(f"ユーザー名は既に使用されています: {response.get('detail')}")

    # ユーザーを作成
    try:
        client.provision_user(
            username=new_username,
            email=new_email,
            password=new_password,
            name=new_name,
            surname=new_surname,
            role=new_role,
        )

        User = get_user_model()
        with transaction.atomic():
            user = User._default_manager.create_user(username=new_username, email=new_email, password=new_password)
            client.create_oidc_identity(user)

    except BizPortalApiError as e:
        raise Exception(f"ユーザーの作成に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"ユーザーの作成中に予期しないエラー: {str(e)}")

    # ユーザーが正常に作成されたことを示すレスポンスを返す
    return HttpResponse("ユーザーが正常に作成されました")

def update_view(request):
    username = request.user.username
    new_email = request.POST.get('email')
    new_name = request.POST.get('name')
    new_surname = request.POST.get('surname')
    new_role = request.POST.get('role')

    try:
        client = BizPortalClient(request)
        client.update_user(username=username, email=new_email, name=new_name, surname=new_surname, role=new_role)
    except BizPortalApiError as e:
        raise Exception(f"ユーザー情報の更新に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"ユーザー情報の更新中に予期しないエラー: {str(e)}")

    return HttpResponse("ユーザー情報が正常に更新されました")

def delete_view(request):
    username = request.POST.get('username')
    subject = request.POST.get('subject')

    try:
        client = BizPortalClient(request)
        client.delete_user(username=username, subject=subject)
    except BizPortalApiError as e:
        raise Exception(f"ユーザーの削除に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"ユーザーの削除中に予期しないエラー: {str(e)}")

    return HttpResponse("ユーザーが正常に削除されました")

def password_reset_view(request):
    username = request.user.username
    email = request.user.email
    # display_company_name を指定するとパスワード再設定ページに表示される会社名を上書きできる
    # 省略時は BizPortal に登録された Company 名が表示される
    tenant_name = request.session.get('tenant_display_name', '')

    try:
        client = BizPortalClient(request)
        # send_reset_email=True（デフォルト）: BizPortal がメール送信し、password_reset_url も返す
        # send_reset_email=False: メール送信を抑制し、password_reset_url のみ返す（クライアント側で管理）
        result = client.password_reset(
            username=username,
            email=email,
            send_reset_email=False,
            display_company_name=tenant_name,
        )
        # 生成されたパスワード再設定 URL をセッションに保存（例: パスワード再設定フローの次のステップで使用）
        request.session['password_reset_url'] = result.get('password_reset_url', '')
    except BizPortalApiError as e:
        raise Exception(f"ユーザーパスワードの再設定に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"ユーザーパスワードの再設定中に予期しないエラー: {str(e)}")

    return HttpResponse("ユーザーパスワードの再設定URLが生成されました")

def password_update_view(request):
    username = request.POST.get('username')
    subject = request.POST.get('subject')
    # password_hash は Django のエンコード済みハッシュ（例: user.password の値、pbkdf2_sha256）
    new_password_hash = request.POST.get('password_hash')

    try:
        client = BizPortalClient(request)
        client.password_update(username=username, subject=subject, password_hash=new_password_hash)
    except BizPortalApiError as e:
        raise Exception(f"ユーザーパスワードの更新に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"ユーザーパスワードの更新中に予期しないエラー: {str(e)}")

    return HttpResponse("ユーザーパスワードが正常に更新されました")

def username_update_view(request):
    username = request.POST.get('username')
    subject = request.POST.get('subject')
    new_username = request.POST.get('new_username')

    try:
        client = BizPortalClient(request)
        client.username_update(username=username, subject=subject, new_username=new_username)
    except BizPortalApiError as e:
        raise Exception(f"ユーザーIDの更新に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"ユーザーIDの更新中に予期しないエラー: {str(e)}")

    return HttpResponse("ユーザーIDが正常に更新されました")
```

### 匿名コンテキストでの呼び出し（アプリケーション資格情報）

`password_reset` と `send_email` はユーザーがまだログインしていない状態（例: ログイン前の「パスワードを忘れた」フロー）でも呼び出せます。この場合、`settings.py` の `OIDC_CLIENT_ID` と `OIDC_CLIENT_SECRET` を HTTP Basic 認証で送信するため、保存済みのアクセストークンは不要です。

```python
def forgot_password_view(request):
    username = request.POST.get('username')
    email = request.POST.get('email')

    try:
        client = BizPortalClient(request)
        result = client.password_reset(
            username=username,
            email=email,
            send_reset_email=True,
        )
    except BizPortalApiError as e:
        raise Exception(f"パスワード再設定メールの送信に失敗: {str(e)}")
    except Exception as e:
        raise Exception(f"パスワード再設定メールの送信中に予期しないエラー: {str(e)}")

    return HttpResponse("パスワード再設定メールを送信しました")
```

## クライアント向けの ブランディング

`django_bizportal_client.context_processors.oidc_portal_branding` コンテキストプロセッサで、以下の変数をテンプレートに提供します。

- `oidc_company_slug`: BizPortal 上の会社識別子
- `oidc_company_name`: BizPortal 上の会社名
- `oidc_installation_name`: BizPortal 上のアプリインストール名

## クライアント向けの セッション延長機能

クライアントアプリのユーザーのセッション、および BizPortal 上のセッションを自動的に延長する機能を提供します。
- `django_bizportal_client.middleware.OIDCSessionCleanupMiddleware`: クライアントアプリの OAuth2 トークンの有効期限が切れている場合に、セッションからトークン情報を削除します。
- `django_bizportal_client.middleware.OIDCSessionRefreshMiddleware`: クライアントアプリのユーザーのセッションが一定期間（24時間以上）経過している場合に、セッションを自動的に更新します。
- `django_bizportal_client.context_processors.oidc_session_refresh`: BizPortal のセッションも更新するための iframe をテンプレートに提供します。

API クライアント (`BizPortalClient`) は、保存済みの refresh token があれば access token の期限切れ時に自動更新を試みます。
