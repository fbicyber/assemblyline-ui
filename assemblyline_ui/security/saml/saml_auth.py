import re
from abc import abstractmethod
from typing import Any, Dict, Optional

from assemblyline_ui.config import LOGGER, AssemblylineDatastore, config
from assemblyline_ui.http_exceptions import AuthenticationException
from flask import redirect, request, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from werkzeug.wrappers import Request, Response

# Code adapted from the python3-saml flask demo:
# https://github.com/SAML-Toolkits/python3-saml/blob/master/demo-flask/index.py


class SamlException(AuthenticationException):
    def __init__(self,
                 last_error_reason: str,
                 errors: list[str]):
        self.last_error_reason: str = last_error_reason
        self.errors: list[str] = errors

    @staticmethod
    @abstractmethod
    def service_type(self) -> str:
        pass

    def __str__(self):
        return f"SAML {self.service_type()} request failed: {self.last_error_reason}"

    def full_error(self):
        errors = "\n".join([f" - {error}\n" for error in self.errors])
        return f"{str(self)}\n{errors}"

    @classmethod
    def from_auth(cls, auth: OneLogin_Saml2_Auth):
        cls(auth.get_last_error_reason(), auth.get_errors())


class SamlSloException(SamlException):
    @staticmethod
    def service_type() -> str:
        return "SLO"


class SamlSlsException(SamlException):
    @staticmethod
    def service_type() -> str:
        return "SLS"


class SamlAcsException(SamlException):
    @staticmethod
    def service_type() -> str:
        return "ACS"


def saml_login() -> Response:

    auth: OneLogin_Saml2_Auth = _make_saml_auth()
    sso_built_url: str = auth.login(return_to=request.host_url)
    session["AuthNRequestID"] = auth.get_last_request_id()
    return redirect(sso_built_url)


def saml_logout() -> Response:
    # SAML SLO
    auth: OneLogin_Saml2_Auth = _make_saml_auth()
    return redirect(auth.logout(name_id=session.get('samlNameId'),
                                session_index=session.get('samlSessionIndex'),
                                nq=session.get('samlNameIdNameQualifier'),
                                name_id_format=session.get('samlNameIdFormat'),
                                spnq=session.get('samlNameIdSPNameQualifier')))


def saml_single_logout() -> Response:
    # SAML SLS
    auth: OneLogin_Saml2_Auth = _make_saml_auth()
    request_id: str = session.get('LogoutRequestID')

    url: str = auth.process_slo(request_id=request_id,
                                delete_session_cb=lambda: session.clear())

    errors: list = auth.get_errors()

    if len(errors) == 0:
        # To avoid open redirect attacks, make sure we're being redirected to the same host
        if url and is_same_host(request.host, url):
            return redirect(url)
    else:
        ex = SamlSlsException.from_auth(auth)
        LOGGER.error(ex.full_error())
        raise ex


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

    # If authentication failed, it'll be noted in `errors`
    # TODO: redirect on failure? something else?
    if len(errors) == 0:
        if "AuthNRequestID" in session:
            del session["AuthNRequestID"]

        session["samlUserdata"] = auth.get_attributes()
        session["samlNameId"] = auth.get_nameid()
        # session["samlNameIdFormat"] = auth.get_nameid_format()
        # session["samlNameIdNameQualifier"] = auth.get_nameid_nq()
        # session["samlNameIdSPNameQualifier"] = auth.get_nameid_spnq()
        # session["samlSessionIndex"] = auth.get_session_index()

        self_url = OneLogin_Saml2_Utils.get_self_url(request_data)

        redirect_to: str = request.form.get("RelayState")

        if redirect_to and self_url != redirect_to:
            # To avoid open redirect attacks, make sure we're being redirected to the same host
            if is_same_host(request.host, redirect_to):
                return redirect(auth.redirect_to(redirect_to))
        else:
            raise Exception("Attempting to redirect to self")
    else:
        ex = SamlAcsException.from_auth(auth)
        LOGGER.error(ex.full_error())
        raise ex


url_regex = re.compile(
    r'^([a-z0-9\.\-]*)://'  # scheme is validated separately
    r'((?:[A-Z0-9_](?:[A-Z0-9-_]{0,61}[A-Z0-9_])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,61}[A-Z0-9_]))|'  # single-label-domain
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    r'(:\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def is_same_host(url1: str, url2: str) -> bool:

    def get_host(url: str):
        match = re.match(url_regex, url1)
        if match:
            groups = match.groups()
            if len(groups) > 0:
                return groups[1]
        return None

    return get_host(url1) == get_host(url2)


def validate_saml_user(username: str,
                       saml_user_data: dict,
                       storage: AssemblylineDatastore) -> (str, list[str]):

    if config.auth.saml.enabled and username:
        if saml_user_data:

            # TODO - not sure how we want to implement this, or if we even want
            # to. If they can log into SAML would we ever want to deny someone
            # access?
            # if not saml_user_data['access']:
            #     raise AuthenticationException("This user is not allowed access to the system")

            cur_user = storage.user.get(username, as_obj=False) or {}

            # Make sure the user exists in AL and is in sync
            if (not cur_user and config.auth.saml.auto_create) or (cur_user and config.auth.saml.auto_sync):
                email: str = _normalize_attribute(saml_user_data["email"]).lower()
                last_name: str = _normalize_attribute(saml_user_data.get("lastName"))
                first_name: str = _normalize_attribute(saml_user_data.get("firstName"))

                # Generate user data from SAML
                data = dict(uname=username,
                            name=f"{last_name}, {first_name}",
                            email=email,
                            password="__NO_PASSWORD__",
                            )
                # TODO - These exist in LDAP, not sure what it's used for
                #     classification=saml_user_data.get("classification"),
                #     type=saml_user_data.get("type"),
                #     roles=saml_user_data.get("roles",
                #     dn=saml_user_data.get("dn")

                # TODO
                # # Get the dynamic classification info
                # data["classification"] = get_dynamic_classification(u_classification, data)

                # Save the updated user
                cur_user.update(data)
                storage.user.save(username, cur_user)

            if cur_user:
                # TODO - read roles from saml info?
                return username, ["R", "W"]
            else:
                raise AuthenticationException("User auto-creation is disabled")

        # TODO - do we want to allow this?
        elif config.auth.internal.enabled:
            # Fallback to internal auth
            pass
        else:
            raise AuthenticationException("Bad SAML user data")

    return None


def _prepare_flask_request(request: Request) -> Dict[str, Any]:
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        # TODO - the https switching disabled because everything redirects to http under the hood. Possibly just a
        # local misconfiguration issue, but it screws up the URL matching later on in `saml_process_assertion`.
        "https": "on",  # if request.scheme == "https" else "off",
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
                               custom_base_path=config.auth.saml.config_dir)


def _normalize_attribute(attribute: Any) -> str:
    # SAML attributes all seem to come through as lists
    if isinstance(attribute, list) and attribute:
        attribute = attribute[0]
    return str(attribute or "")
