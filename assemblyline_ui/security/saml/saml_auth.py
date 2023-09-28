from typing import Any, Dict, Optional

from assemblyline_ui.config import LOGGER, config
from flask import redirect, request, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from werkzeug.wrappers import Request, Response

# Code adapted from the python3-saml flask demo:
# https://github.com/SAML-Toolkits/python3-saml/blob/master/demo-flask/index.py


def saml_login() -> Response:
    try:
        auth: OneLogin_Saml2_Auth = _make_saml_auth()
    except Exception as ex:
        foo = ex

    sso_built_url: str = auth.login()
    # session["AuthNRequestID"] = auth.get_last_request_id()
    return redirect(sso_built_url)


def saml_logout() -> Response:
    # SAML SLO
    auth: OneLogin_Saml2_Auth = _make_saml_auth()
    return redirect(auth.logout(name_id=session.get('samlNameId'),
                                session_index=session.get('samlSessionIndex'),
                                nq=session.get('samlNameIdNameQualifier'),
                                name_id_format=session.get('samlNameIdFormat'),
                                spnq=session.get('samlNameIdSPNameQualifier')))


def saml_single_logout() -> Optional[Response]:
    # SAML SLS
    auth: OneLogin_Saml2_Auth = _make_saml_auth()
    request_id: str = session.get('LogoutRequestID')

    url: str = auth.process_slo(request_id=request_id,
                                delete_session_cb=lambda: session.clear())

    errors: list = auth.get_errors()

    if len(errors) == 0:
        if url:
            # To avoid 'Open Redirect' attacks, before execute the redirection confirm
            # the value of the url is a trusted URL.
            return redirect(url)
    else:
        errors = [f" - {error}\n" for error in errors]
        LOGGER.error(f"SAML SLO request failed: {auth.get_last_error_reason()}\n{''.join(errors)}")


def saml_process_assertion() -> Response:
    '''
    A SAML Assertion Consumer Service (ACS) is a web service endpoint that is
    used in the SAML authentication and authorization protocol. The ACS is a
    service provided by the service provider (SP) that receives and processes
    SAML assertions from the identity provider (IdP). The ACS is responsible
    for extracting the relevant information from the SAML assertion, such as
    the user's attributes or the authentication event, and using that
    information to grant the user access to the protected resource.
    '''
    request_data: Dict[str, Any] = _prepare_flask_request(request)
    auth: OneLogin_Saml2_Auth = _make_saml_auth(request_data)
    request_id: str = session.get("AuthNRequestID")

    auth.process_response(request_id=request_id)
    errors: list = auth.get_errors()

    # not_auth_warn = not auth.is_authenticated()
    if len(errors) == 0:
        if "AuthNRequestID" in session:
            del session["AuthNRequestID"]

        session["samlUserdata"] = auth.get_attributes()
        session["samlNameId"] = auth.get_nameid()
        session["samlNameIdFormat"] = auth.get_nameid_format()
        session["samlNameIdNameQualifier"] = auth.get_nameid_nq()
        session["samlNameIdSPNameQualifier"] = auth.get_nameid_spnq()
        session["samlSessionIndex"] = auth.get_session_index()

        self_url = OneLogin_Saml2_Utils.get_self_url(request_data)

        if "RelayState" in request.form and self_url != request.form["RelayState"]:
            # To avoid 'Open Redirect' attacks, before execute the redirection confirm
            # the value of the request.form["RelayState"] is a trusted URL.
            return redirect(auth.redirect_to(request.form["RelayState"]))
    else:
        errors = [f" - {error}\n" for error in errors]
        LOGGER.error(f"SAML SLO request failed: {auth.get_last_error_reason()}\n{''.join(errors)}")


def _prepare_flask_request(request: Request) -> Dict[str, Any]:
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # "lowercase_urlencoding": True,
        "post_data": request.form.copy()
    }


def _make_saml_auth(request_data: Dict[str, Any] = None) -> OneLogin_Saml2_Auth:
    request_data: Dict[str, Any] = request_data or _prepare_flask_request(request)
    return OneLogin_Saml2_Auth(request_data,
                               custom_base_path=config.auth.saml.path)
