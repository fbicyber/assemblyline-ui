
from flask import request

from assemblyline.common import forge
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE

SUB_API = 'seed'
seed_api = make_subapi_blueprint(SUB_API)
seed_api._doc = "Manage configuration seeds"


# noinspection PyUnusedLocal
@seed_api.route("/", methods=["PUT"])
@api_login(require_admin=True)
def save_seed(**kwargs):
    """
    Save the configuration seed to the system
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    { 
     "KEY": "value",  # Dictionary of key/value pair  
     ...
    }
    
    Result example:
    { 
     "success": true  # Was the update successful?   
    }
    """
    seed = request.json
    old_seed = STORAGE.get_blob("seed")

    STORAGE.save_blob("previous_seed", old_seed)
    STORAGE.save_blob("seed", seed)

    return make_api_response({"success": True})


# noinspection PyUnusedLocal
@seed_api.route("/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_seed(**kwargs):
    """
    Get the currently running configuration seed
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { 
     "KEY": "value",  # Dictionary of key/value pair  
     ...
    }
    """
    return make_api_response(STORAGE.get_blob("seed"))


# noinspection PyUnusedLocal
@seed_api.route("/previous/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_previous_seed(**kwargs):
    """
    Get the previous configuration seed
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { 
     "KEY": "value",  # Dictionary of key/value pair  
     ...
    }
    """
    return make_api_response(STORAGE.get_blob("previous_seed") or {})


# noinspection PyUnusedLocal
@seed_api.route("/default/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_default_seed(**kwargs):
    """
    Get the default configuration seed
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { 
     "KEY": "value",  # Dictionary of key/value pair  
     ...
    }
    """
    return make_api_response(STORAGE.get_blob("original_seed") or {})


# noinspection PyUnusedLocal
@seed_api.route("/source/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_source_seed(**kwargs):
    """
    Get the default configuration seed

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "KEY": "value",  # Dictionary of key/value pair
     ...
    }
    """
    seed_yml = STORAGE.get_blob("seed_yml")
    if not seed_yml:
        return make_api_response({})
    seed = forge.get_config(yml_config=seed_yml, static=True)

    # TODO: Should we still need to merged the service configuration ?
    #services_to_register = seed['services']['master_list']

    #for service, svc_detail in services_to_register.iteritems():
    #    seed['services']['master_list'][service] = get_merged_svc_config(service, svc_detail, LOGGER)

    return make_api_response(seed)
