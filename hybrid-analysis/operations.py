""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import ast, io, json, requests
from connectors.core.connector import get_logger, ConnectorError
from cshmac.requests import HmacAuth
from django.conf import settings
from integrations.crudhub import maybe_json_or_raise
from connectors.cyops_utilities.builtins import download_file_from_cyops
from integrations.crudhub import make_request
from os.path import join

logger = get_logger('hybrid-analysis')

GET_FEED = '/api/v2/feed/latest'
GET_REPORT = '/api/v2/report/{ID}/summary'
SUBMIT_FILE = '/api/v2/submit/file'
GET_ENVIRONMENTS = '/api/v2/system/environments'
GET_QUOTA = '/api/v2/key/submission-quota'
KEY_LIMITS = '/api/v2/key/current'
SEARCH_HASHES = '/api/v2/search/hashes'
SAMPLE_DROPPED_FILES = '/api/v2/report/{ID}/dropped-files'
SAMPLE_SCREENSHOTS = '/api/v2/report/{ID}/screenshots'
SEARCH = '/api/v2/search/terms'
SUBMISSION_STATE = '/api/v2/report/{ID}/state'
URL_QUICK_SCAN = '/api/v2/quick-scan/url'
SUBMIT_URL = '/api/v2/submit/url'


def str_to_list(input_str):
    if isinstance(input_str, str) and len(input_str) > 0:
        return [str(x.strip()) for x in input_str.split(',')]
    elif isinstance(input_str, list):
        return input_str
    else:
        return []


def _get_input(params, key, type):
    ret_val = params.get(key, None)
    if ret_val:
        if isinstance(ret_val, bytes):
            ret_val = ret_val.decode('utf-8')
        if isinstance(ret_val, type):
            return ret_val
        else:
            logger.info(
                "Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter Type is: {1}".format(
                    str(key), str(type)))
            raise ConnectorError(
                "Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter Type is: {1}".format(str(key),
                                                                                                             str(type)))
    else:
        if ret_val == {} or ret_val == [] or ret_val == 0:
            return ret_val
        return None


def _make_request(url, method, body=None):
    bodyless_methods = ['head', 'get']
    if method.lower() in bodyless_methods:
        body = None
    if type(body) == str:
        try:
            body = ast.literal_eval(body)
        except Exception:
            pass
    url = settings.CRUD_HUB_URL + url
    logger.info('Starting request: {0} , {1}'.format(method, url))
    auth = HmacAuth(url, method, settings.APPLIANCE_PUBLIC_KEY, settings.APPLIANCE_PRIVATE_KEY, json.dumps(body))
    response = requests.request(method, url, auth=auth, json=body, verify=False)
    return response.content


def _get_config(config):
    api_key = _get_input(config, "api_key", str)
    secret_key = _get_input(config, "secret_key", str)
    verify_ssl = config.get("verify_ssl")
    server_url = config.get("server_url", None)
    if server_url[:7] != 'http://' and server_url[:8] != 'https://':
        server_url = 'https://{}'.format(server_url)
    return api_key, secret_key, server_url, verify_ssl


def _api_request(method, url, config, payload={}, header=None, file={}, params={}, json_format=True):
    try:
        api_key, secret_key, server_url, verify_ssl = _get_config(config)
        url = server_url + url
        header = {'api-key': api_key, 'User-Agent': 'Python-Agent'}
        api_response = requests.request(method=method, url=url, headers=header, params=params, data=payload, files=file,
                                        verify=verify_ssl)
        if api_response.ok:
            if json_format == True:
                return json.loads(api_response.content.decode('utf-8'))
            else:
                return api_response.content
        else:
            logger.info('Fail To request API {0} response is : {1}'.format(str(url), str(api_response.content)))
            raise ConnectorError('Fail To request API {0} response is :{1}'.format(str(url), str(api_response.content)))
    except Exception as Err:
        raise ConnectorError(Err)


def _upload_file_to_cyops(file_name, file_content, file_type):
    try:
        url = settings.CRUD_HUB_URL + '/api/3/files'
        auth = HmacAuth(url, 'POST', settings.APPLIANCE_PUBLIC_KEY,
                        settings.APPLIANCE_PRIVATE_KEY,
                        settings.APPLIANCE_PUBLIC_KEY.encode('utf-8'))
        files = {'file': (file_name, file_content, file_type, {'Expire': 0})}
        response = requests.post(url, auth=auth, files=files, verify=False)
        response = maybe_json_or_raise(response)
        logger.info('File upload complete {}'.format(str(response)))
        file_id = response['@id']
        file_description = file_name
        attach_response = _make_request('/api/3/attachments', 'POST',
                                        {'name': file_name, 'file': file_id, 'description': file_description})
        logger.info('attach file complete: {}')
        return attach_response
    except Exception as err:
        logger.exception('An exception occurred {}'.format(str(err)))
        raise ConnectorError('An exception occurred {}'.format(str(err)))


def _get_params_in_bulk(params, params_list):
    try:
        params_values = {}
        for var in params_list:
            params_values.update(
                {var["field_name"]: _get_input(params, var["field_name"], var["field_type"])}) if _get_input(params,
                                                                                                             var[
                                                                                                                 "field_name"],
                                                                                                             var[
                                                                                                                 "field_type"]) else None
        return params_values
    except Exception as Err:
        raise ConnectorError(str(Err))


def _get_url_from_job_id_or_file_hash(params, api):
    try:
        job_id = _get_input(params, "job_id", str)
        file_hash = _get_input(params, "file_hash", str)
        environmentId = _get_input(params, "environmentId", int)
        if file_hash and environmentId:
            file_hash = '{0}:{1}'.format(file_hash, environmentId)
            url = api.format(ID=file_hash)
        elif job_id:
            url = api.format(ID=job_id)
        else:
            logger.exception(
                "Required parameter is missing expected parameters are File SHA256 and Environment ID or Job ID")
            raise ConnectorError(
                "Required parameter is missing expected parameters are File SHA256 and Environment ID or Job ID")
        return url
    except Exception as Err:
        raise ConnectorError(Err)


def check_health(config):
    try:
        if _api_request("get", KEY_LIMITS, config):
            return True
    except Exception as Err:
        logger.exception(str(Err))
        if "The provided API key is incompatible with API v2. Please regenerate it and try again" in str(Err):
            raise ConnectorError("The provided API key is incompatible with API v2. Please regenerate it and try again")
        elif "Max retries exceeded with url" in str(Err):
            raise ConnectorError("Invalid endpoint or credentials")
        else:
            raise ConnectorError(str(Err))


def get_environment(config, params):
    try:
        return _api_request("get", GET_ENVIRONMENTS, config)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def get_api_quota(config, params):
    try:
        return _api_request("get", GET_QUOTA, config)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def get_feed(config, params):
    try:
        url = '{0}'.format(GET_FEED)
        return _api_request("get", url, config)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def get_report(config, params):
    try:
        url = _get_url_from_job_id_or_file_hash(params, GET_REPORT)
        return _api_request("get", url, config)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def get_sample_dropped_file(config, params):
    try:
        url = _get_url_from_job_id_or_file_hash(params, SAMPLE_DROPPED_FILES)
        file_data = _api_request("get", url, config, json_format=False)
        if isinstance(file_data, bytes):
            file_obj = io.BytesIO(file_data)
        else:
            file_obj = io.StringIO(file_data)
        upload_response = _upload_file_to_cyops("Drop_File", file_obj, 'application/octet-stream')
        return json.loads(upload_response.decode('utf-8'))
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def get_sample_screenshots(config, params):
    try:
        result = {}
        is_attach = _get_input(params, "is_attach", bool)
        url = _get_url_from_job_id_or_file_hash(params, SAMPLE_SCREENSHOTS)
        if is_attach:
            all_screenshots = _api_request("get", url, config)
            for screen in all_screenshots:
                if isinstance(screen["image"], bytes):
                    file_obj = io.BytesIO(screen["image"])
                else:
                    file_obj = io.StringIO(screen["image"])
                upload_response = _upload_file_to_cyops(screen["name"], file_obj, 'application/octet-stream')
                result.update({screen["name"]: json.loads(upload_response.decode('utf-8'))})
            return result
        else:
            return _api_request("get", url, config)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def get_submitted_sample_state(config, params):
    try:
        url = _get_url_from_job_id_or_file_hash(params, SUBMISSION_STATE)
        return _api_request("get", url, config)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def conditional_search(config, params):
    try:
        verdict_value = ["Whitelisted", "No Verdict", "No Specific Threat", "Suspicious", "Malicious"]
        search_params = [{"field_name": "filename", "field_type": str},
                         {"field_name": "filetype", "field_type": str},
                         {"field_name": "filetype_desc", "field_type": str},
                         {"field_name": "verdict", "field_type": str},
                         {"field_name": "av_detect", "field_type": str},
                         {"field_name": "vx_family", "field_type": str},
                         {"field_name": "tag", "field_type": str},
                         {"field_name": "port", "field_type": int},
                         {"field_name": "host", "field_type": str},
                         {"field_name": "domain", "field_type": str},
                         {"field_name": "url", "field_type": str},
                         {"field_name": "similar_to", "field_type": str},
                         {"field_name": "context", "field_type": str},
                         {"field_name": "imp_hash", "field_type": str},
                         {"field_name": "ssdeep", "field_type": str},
                         {"field_name": "authentihash", "field_type": str}]
        search_params_values = _get_params_in_bulk(params, search_params)
        search_params_values.update(
            {"verdict": int(verdict_value.index(search_params_values.get("verdict"))) + 1}) if search_params_values.get(
            "verdict") else None
        return _api_request("post", SEARCH, config, payload=search_params_values)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def url_quick_scan(config, params):
    try:
        url_quick_scan_payload = {
            'scan_type': 'all',
            'url': _get_input(params, "url_to_scan", str),
            'no_share_third_party': params.get('no_share_third_party') if params.get(
                'no_share_third_party') is not None else True,
            'allow_community_access': params.get('allow_community_access') if params.get(
                'allow_community_access') is not None else True,
        }

        return _api_request("post", URL_QUICK_SCAN, config, payload=url_quick_scan_payload)

    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def hashes_search(config, params):
    try:
        search_hashes_payload = {'hashes[]': str_to_list(params.get('hashcodes'))}
        return _api_request("post", SEARCH_HASHES, config, payload=search_hashes_payload)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


def handle_params(params):
    value = str(params.get('value'))
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if not value.startswith('/api/3/attachments/'):
            value = '/api/3/attachments/{0}'.format(value)
        attachment_data = make_request(value, 'GET')
        file_iri = attachment_data['file']['@id']
        file_name = attachment_data['file']['filename']
        logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
        return file_iri, file_name
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError(
            'Requested resource could not be found with input type Attachment ID and value "{0}"'.format
            (value.replace('/api/3/attachments/', '')))


def submit_file(config, params):
    try:
        submit_file_params = [{"field_name": "environment_id", "field_type": int},
                              {"field_name": "no_share_third_party", "field_type": bool},
                              {"field_name": "no_hash_lookup", "field_type": bool},
                              {"field_name": "action_script", "field_type": str},
                              {"field_name": "hybrid_analysis", "field_type": bool},
                              {"field_name": "experimental_anti_evasion", "field_type": bool},
                              {"field_name": "script_logging", "field_type": bool},
                              {"field_name": "input_sample_tampering", "field_type": bool},
                              {"field_name": "tor_enabled_analysis", "field_type": bool},
                              {"field_name": "offline_analysis", "field_type": bool},
                              {"field_name": "email", "field_type": str},
                              {"field_name": "properties", "field_type": str},
                              {"field_name": "comment", "field_type": str},
                              {"field_name": "custom_date_time", "field_type": str},
                              {"field_name": "custom_cmd_line", "field_type": str},
                              {"field_name": "custom_run_time", "field_type": int},
                              {"field_name": "submit_name", "field_type": str},
                              {"field_name": "priority", "field_type": int},
                              {"field_name": "document_password", "field_type": str},
                              {"field_name": "environment_variable", "field_type": str}
                              ]
        submit_file_params_values = _get_params_in_bulk(params, submit_file_params)
        file_iri, file_name = handle_params(params)
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        logger.info("File Path: {0}".format(file_path))
        with open(file_path, 'rb') as attachment:
            content = attachment.read()
            if content:
                files = {'file': content}
                return _api_request("post", SUBMIT_FILE, config, payload=submit_file_params_values, file=files)
    except Exception as Err:
        logger.exception("{0}".format(str(Err)))
        raise ConnectorError("{0}".format(str(Err)))


def submit_url(config, params):
    try:
        submit_url_params = [{"field_name": "url", "field_type": str},
                             {"field_name": "environment_id", "field_type": int},
                             {"field_name": "no_share_third_party", "field_type": bool},
                             {"field_name": "no_hash_lookup", "field_type": bool},
                             {"field_name": "priority", "field_type": int},
                             {"field_name": "action_script", "field_type": str},
                             {"field_name": "hybrid_analysis", "field_type": bool},
                             {"field_name": "experimental_anti_evasion", "field_type": bool},
                             {"field_name": "script_logging", "field_type": bool},
                             {"field_name": "input_sample_tampering", "field_type": bool},
                             {"field_name": "tor_enabled_analysis", "field_type": bool},
                             {"field_name": "email", "field_type": str},
                             {"field_name": "properties", "field_type": str},
                             {"field_name": "comment", "field_type": str},
                             {"field_name": "custom_date_time", "field_type": str},
                             {"field_name": "custom_run_time", "field_type": int},
                             {"field_name": "environment_variable", "field_type": str}
                             ]
        submit_url_params_values = _get_params_in_bulk(params, submit_url_params)
        return _api_request("post", SUBMIT_URL, config, payload=submit_url_params_values)
    except Exception as Err:
        logger.exception("Fail : {}".format(str(Err)))
        raise ConnectorError(Err)


hybrid_analysis_ops = {
    'get_report': get_report,
    'submit_file': submit_file,
    'get_environment': get_environment,
    'get_api_quota': get_api_quota,
    'get_sample_dropped_file': get_sample_dropped_file,
    'get_sample_screenshots': get_sample_screenshots,
    'get_submitted_sample_state': get_submitted_sample_state,
    'conditional_search': conditional_search,
    'get_feed': get_feed,
    'hashes_search': hashes_search,
    'url_quick_scan': url_quick_scan,
    'submit_url': submit_url

}
