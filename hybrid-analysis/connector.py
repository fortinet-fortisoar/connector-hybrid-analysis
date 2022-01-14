from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import check_health, hybrid_analysis_ops
logger = get_logger('hybrid analysis')

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
        return check_health(config)
