# django-bizportal-client

BizPortal を OIDC IdP として使う Django 5+ 向け最小クライアント連携パッケージです。

## インストール

```bash
pip install git+https://github.com/ts-taisei/BizPortalClients.git#subdirectory=django_bizportal_client
```

## 基準設定

`settings.py` に以下を設定します。

```python
INSTALLED_APPS = [
    # ...
    'django_bizportal_client',
]

TEMPLATES = [
    {
        # ...
        'OPTIONS': {
            'context_processors': [
                # ...
                'django_bizportal_client.context_processors.oidc_portal_branding',
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
OIDC_LOGOUT_URL = 'https://bizportal.example.com/o/logout/'
OIDC_STATE_SALT = 'oidc-state-v1'

# 任意設定
OIDC_SCOPE = 'openid email'
OIDC_STATE_MAX_AGE_SECONDS = 300
OIDC_TIMEOUT_SECONDS = 10
OIDC_AUTO_CREATE_USER = False
OIDC_IDENTITY_MODEL = 'django_bizportal_client.OIDCIdentity'
```

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
- `provision_user`: BizPortal 上でユーザーを作成
- `create_oidc_identity`: OIDCIdentity レコードを作成

### クライアントコードの例です。

```python
from django_bizportal_client.client import BizPortalClient, BizPortalApiError
from django.contrib.auth import get_user_model
from django.db import transaction

def my_view(request):
    new_username = request.POST.get('username')
    new_email = request.POST.get('email')
    new_password = request.POST.get('password')
    new_name = request.POST.get('name')
    new_surname = request.POST.get('surname')

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
        client.provision_user(new_username, new_email, new_password, name=new_name, surname=new_surname)

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
```

## クライアント向けの ブランディング

`django_bizportal_client.context_processors.oidc_portal_branding` コンテキストプロセッサで、以下の変数をテンプレートに提供します。

- `oidc_company_slug`: BizPortal 上の会社識別子
- `oidc_company_name`: BizPortal 上の会社名
- `oidc_installation_name`: BizPortal 上のアプリインストール名
