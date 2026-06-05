# AGENTS.md
BizPortalClients は BizPortal を OIDC IdP として利用するクライアントアプリ向けの多フレームワーク対応パッケージ群です。

## ガイドライン統合ポリシー（正本）
- 本リポジトリの AI エージェント向け公式ガイドラインの唯一の参照元は、この `AGENTS.md`（ルート）とする。
- ドキュメントおよび AI エージェント向けリポジトリ概要は日本語を正本とする。
- 既存ガイドラインは意味を変えず維持し、新規ガイドラインは上書きせず追記で管理する。
- 競合がある場合は削除/置換ではなく、適用条件・補足・優先順位を明記して非破壊で整理する。

## リポジトリ構成

| ディレクトリ | 状態 | 概要 |
|---|---|---|
| `django_bizportal_client/` | 本番対応 | Django 5.2+ 向け OIDC クライアントパッケージ (v0.8.0) |
| `flask_bizportal_client/` | スタブ | Flask 向け（未実装） |
| `laravel_bizportal_client/` | スタブ | Laravel 向け（未実装） |

## django-bizportal-client パッケージ

### 言語/実行環境
- Python 3.12 以上

### 依存パッケージ
- Django >= 5.2, < 6.0
- Authlib >= 1.3, < 2.0
- requests >= 2.31

### バージョン管理
- バージョンは `django_bizportal_client/__init__.py` の `__version__` で管理する
- `pyproject.toml` の `dynamic = ["version"]` を通じて setuptools が参照する
- git タグ命名規則：`dja-<version>` (例: `dja-0.8.0`)

### パッケージ主要モジュール
- `backends.py`: `BizPortalOIDCBackend` 認証バックエンド
- `client.py`: BizPortal 管理 API クライアント (`BizPortalClient`)
- `models.py`: `OIDCIdentity` モデル
- `middleware.py`: セッションクリーンアップ・自動更新ミドルウェア
- `views.py`: OIDC フロー用エンドポイント（prepare / callback / login / logout）
- `context_processors.py`: テンプレート向けコンテキスト提供
- `settings.py`: 設定マネージャー
- `urls.py`: URL ルーティング定義
- `admin.py`: Django 管理サイト統合
- `management/commands/createsuperuser.py`: OIDC ID 紐付け対応のスーパーユーザー作成コマンド

## バリデーションコマンド
- `python -m compileall django_bizportal_client/`

## 開発環境セットアップ
### 前提条件
- Python 3.12 以上
- pip

1. リポジトリを取得
   ```bash
   git clone <repository-url>
   cd BizPortalClients
   ```
2. パッケージを編集可能モードでインストール
   ```bash
   pip install -e django_bizportal_client/
   ```

## 開発ガイドライン
- テスト方針: 本リポジトリではテストの作成・実行は開発フローに含めない。
- スクリーンショット方針: 視覚的ドキュメント目的のスクリーンショットは取得しない。
- コードスタイル:
  - Django のベストプラクティスと既存実装パターンに従う
  - 不要なコメントやドキュメント追記は行わない
  - コメントが必要な場合（非常に複雑なロジックなど）は、日本語で簡潔かつ明確に記述する
  - モジュール名、クラス名、関数名などは英語で表記する
  - 行末の不要な空白を残さない
  - 変更は最小かつ焦点を絞り、既存スタイルとの一貫性を維持する

## 補足
- 本パッケージは Authorization Code Flow with PKCE を実装している
- `state` パラメーターは Django の署名機能で保護されており、CSRF・リプレイ攻撃を防ぐ
- 新規フレームワーク向けクライアントの追加は、対応するディレクトリ配下に独立したパッケージとして実装する
