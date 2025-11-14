"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

"""
HYBRID ANALYSIS
"""

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import check_health as ops_check_health, hybrid_analysis_ops
from .constants import MACRO_LIST

try:
    from integrations.crudhub import make_request
    from django.conf import settings
except:
    pass

logger = get_logger('hybrid-analysis')


class Hybrid_Analysis(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation:[{}]'.format(operation))
        operation = hybrid_analysis_ops.get(operation, None)
        if not operation:
            logger.info('Unsupported operation [{}]'.format(operation))
            raise ConnectorError('Unsupported operation')
        result = operation(config, params)
        return result

    def check_health(self, config):
        try:
            logger.info('executing check health')
            connection_response = ops_check_health(config)
            return connection_response
        except Exception as exp:
            logger.exception(str(exp))
            raise ConnectorError(str(exp))

    def del_micro(self, config):
        if not settings.LW_AGENT:
            for macro in MACRO_LIST:
                try:
                    resp = make_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                    if resp['hydra:member']:
                        logger.info("resetting global variable '%s'" % macro)
                        macro_id = resp['hydra:member'][0]['id']
                        resp = make_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
                except Exception as e:
                    logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config, active):
        self.del_micro(config)

    def on_delete_config(self, config):
        self.del_micro(config)
