import uuid

from flask import request
from riak import RiakError

from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE, CLASSIFICATION
from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore import SearchException

SUB_API = 'workflow'
workflow_api = make_subapi_blueprint(SUB_API)
workflow_api._doc = "Manage the different workflows of the system"


# noinspection PyBroadException
def verify_query(query):
    """Ensure that a workflow query can be executed."""
    try:
        STORAGE.search_alert(query)
    except SearchException as error:
        return False, str(error)
    except Exception:  # If an error occurred in this block we are 100% blaming the user query
        return False, 'Invalid Query'
    return True, ''


@workflow_api.route("/", methods=["PUT"])
@api_login(allow_readonly=False)
def add_workflow(**kwargs):
    """
    Add a workflow to the system
    
    Variables: 
    None

    Arguments: 
    None
    
    Data Block:
    {                        
     "name": "Workflow name",    # Name of the workflow
     "classification": "",       # Max classification for workflow
     "label": ['label1'],        # Labels for the workflow
     "priority": "LOW",          # Priority of the workflow
     "status": "MALICIOUS",      # Status of the workflow
     "query": "*:*"              # Query to match the data
    } 
    
    Result example:
    {
     "success": true             # Saving the user info succeded 
    }
    """
    
    data = request.json

    name = data.get('name', None)
    query = data.get('query', None)

    if not name:
        return make_api_response({"success": False}, err="Name field is required", status_code=400)

    if not query:
        return make_api_response({"success": False}, err="Query field is required", status_code=400)

    success, _ = verify_query(query)
    if not success:
        return make_api_response({"success": False}, err="Query contains an error", status_code=400)

    uname = kwargs['user']['uname']
    date = now_as_iso()
    data.update({
        "creator": uname,
        "creation_date": date,
        "edited_by": uname,
        "last_edit": date
    })

    STORAGE.save_workflow(str(uuid.uuid4()), data)
    return make_api_response({"success": True})


@workflow_api.route("/<workflow_id>/", methods=["POST"])
@api_login(allow_readonly=False)
def edit_workflow(workflow_id, **kwargs):
    """
    Edit a workflow.

    Variables:
    workflow_id    => ID of the workflow to edit

    Arguments:
    None

    Data Block:
    {
     "name": "Workflow name",    # Name of the workflow
     "classification": "",       # Max classification for workflow
     "label": ['label1'],        # Labels for the workflow
     "priority": "LOW",          # Priority of the workflow
     "status": "MALICIOUS",      # Status of the workflow
     "query": "*:*"              # Query to match the data
    }

    Result example:
    {
     "success": true             # Saving the user info succeded
    }
    """
    data = request.json
    name = data.get('name', None)
    query = data.get('query', None)

    if not name:
        return make_api_response({"success": False}, err="Name field is required", status_code=400)

    if not query:
        return make_api_response({"success": False}, err="Query field is required", status_code=400)

    success, _ = verify_query(query)
    if not success:
        return make_api_response({"success": False}, err="Query contains an error", status_code=400)

    wf = STORAGE.get_workflow(workflow_id)
    if wf:
        uname = kwargs['user']['uname']
        date = now_as_iso()

        data.update({
            "edited_by": uname,
            "last_edit": date
        })

        STORAGE.save_workflow(workflow_id, data)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False},
                                 err="Workflow ID %s does not exist" % workflow_id,
                                 status_code=404)


@workflow_api.route("/<workflow_id>/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
def get_workflow(workflow_id, **kwargs):
    """
    Load the user account information.
    
    Variables: 
    workflow_id       => ID of the workflow
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {                        
     "name": "Workflow name",    # Name of the workflow
     "classification": "",       # Max classification for workflow
     "label": ['label1'],        # Labels for the workflow
     "priority": "LOW",          # Priority of the workflow
     "status": "MALICIOUS",      # Status of the workflow
     "query": "*:*"              # Query to match the data
    } 
    """
    user = kwargs['user']
    wf = STORAGE.get_workflow(workflow_id)
    if wf:
        if CLASSIFICATION.is_accessible(user['classification'], wf['classification']):
            return make_api_response(wf)
        else:
            return make_api_response({},
                                     err="You're not allowed to view workflow ID: %s" % workflow_id,
                                     status_code=403)
    else:
        return make_api_response({},
                                 err="Workflow ID %s does not exist" % workflow_id,
                                 status_code=404)


@workflow_api.route("/labels/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
def list_workflow_labels(**kwargs):
    """
    List all labels from the workflows

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [
      "LABEL1",
      "LABEL2"
      ...
    ]
    """
    user = kwargs['user']
    return make_api_response(STORAGE.list_workflow_labels(access_control=user['access_control']))


@workflow_api.route("/list/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
def list_workflows(**kwargs):
    """
    List all workflows of the system.
    
    Variables:
    None
    
    Arguments: 
    offset        =>  Offset in the workflow bucket
    length        =>  Max number of workflow returned
    filter        =>  Filter to apply to the workflow list
    
    Data Block:
    None
    
    Result example:
    {
     "count": 100,               # Max number of workflows
     "items": [{                 # List of workflows
       "name": "Workflow name",    # Name of the workflow
       "classification": "",       # Max classification for workflow
       "label": ['label1'],        # Labels for the workflow
       "priority": "LOW",          # Priority of the workflow
       "status": "MALICIOUS",      # Status of the workflow
       "query": "*:*"              # Query to match the data
     } , ...],
     "total": 10,                # Total number of workflows
     "offset": 0                 # Offset in the workflow bucket
    }
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', None)
    
    try:
        return make_api_response(STORAGE.list_workflows(start=offset, rows=length, query=query,
                                                        access_control=user['access_control']))
    except RiakError as e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)


@workflow_api.route("/<workflow_id>/", methods=["DELETE"])
@api_login(audit=False, allow_readonly=False)
def remove_workflow(workflow_id, **_):
    """
    Remove the specified workflow.
    
    Variables: 
    workflow_id       => ID of the workflow to remove
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {                        
     "success": true  # Was the remove successful?
    } 
    """
    wf = STORAGE.get_workflow(workflow_id)
    if wf:
        STORAGE.delete_workflow(workflow_id)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False},
                                 err="Workflow ID %s does not exist" % workflow_id,
                                 status_code=404)
