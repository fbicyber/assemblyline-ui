from typing import Any, Dict, Optional

from assemblyline.odm.models.user import load_roles_form_acls
from assemblyline_ui.config import LOGGER, AssemblylineDatastore, config
from assemblyline_ui.helper.user import API_PRIV_MAP
from assemblyline_ui.http_exceptions import AuthenticationException
from flask import redirect, request, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from werkzeug.wrappers import Request, Response

# Code adapted from the python3-saml flask demo:
# https://github.com/SAML-Toolkits/python3-saml/blob/master/demo-flask/index.py


def saml_login() -> Response:

    auth: OneLogin_Saml2_Auth = _make_saml_auth()

    # TODO don't hardcode `return_to` value
    sso_built_url: str = auth.login(return_to="https://ubuntu2/")
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

        if "RelayState" in request.form and self_url != request.form["RelayState"]:
            # To avoid 'Open Redirect' attacks, before execute the redirection confirm
            # the value of the request.form["RelayState"] is a trusted URL.
            return redirect(auth.redirect_to(request.form["RelayState"]))
    else:
        errors: list = [f" - {error}\n" for error in errors]
        error_msg: str = f"SAML ACS request failed: {auth.get_last_error_reason()}\n{''.join(errors)}"
        LOGGER.error(error_msg)
        # TODO - need better error handling
        raise Exception(error_msg)


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
                # TODO
                # u_classification = ldap_info['classification']

                # Normalize email address
                email = saml_user_data["email"]
                if isinstance(email, list) and email:
                    email = email[0]
                if isinstance(email, str) is not None:
                    email = email.lower()

                # Generate user data from SAML
                data = dict(uname=username,
                            name=f"{saml_user_data['lastName']}, {saml_user_data['firstName']}",
                            email=email,
                            password="__NO_PASSWORD__",
                            )
                # TODO
                #     classification=u_classification,
                #     type=ldap_info['type'],
                #     roles=ldap_info['roles'],
                #     dn=ldap_info['dn']

                # TODO
                # # Get the dynamic classification info
                # data['classification'] = get_dynamic_classification(u_classification, data)

                # TODO
                # # Save the user avatar avatar from ldap
                # img_data = get_attribute(ldap_info, config.auth.ldap.image_field, safe=False)
                # if img_data:
                #     b64_img = base64.b64encode(img_data).decode()
                #     avatar = f'data:image/{config.auth.ldap.image_format};base64,{b64_img}'
                #     storage.user_avatar.save(username, avatar)

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
