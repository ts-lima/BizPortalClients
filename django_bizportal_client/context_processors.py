from django_bizportal_client.settings import get_required_setting


def oidc_portal_branding(request):
    return {
        "oidc_company_slug": request.session.get("oidc_company_slug", ""),
        "oidc_company_name": request.session.get("oidc_company_name", ""),
        "oidc_installation_name": request.session.get("oidc_installation_name", ""),
    }


def oidc_session_refresh(request):
    if getattr(request, 'oidc_session_refreshed', False):
        src = f"{get_required_setting('OIDC_ISSUER_URL')}oidc/session/refresh/"
        iframe = f'<iframe src="{src}" title="OIDC Session Refresh" loading="eager" hidden></iframe>'
        return {
            'oidc_session_refreshed': True,
            'oidc_session_refreshed_at': getattr(request, 'oidc_session_refreshed_at', None),
            'oidc_session_refresh_iframe': iframe
        }
    return {
        'oidc_session_refreshed': False,
        'oidc_session_refreshed_at': None,
        'oidc_session_refresh_iframe': '',
    }
