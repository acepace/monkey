import json
import logging
from contextlib import closing

import requests
from requests.exceptions import Timeout, ConnectionError

import infection_monkey.config
from infection_monkey.network.HostFinger import HostFinger
from common.data.network_consts import ES_SERVICE

ES_PORT = 9200
ES_HTTP_TIMEOUT = 5
LOG = logging.getLogger(__name__)
__author__ = 'danielg'


class ElasticFinger(HostFinger):
    """
        Fingerprints elastic search clusters, only on port 9200
    """
    _SCANNED_SERVICE = 'Elastic search'

    def __init__(self):
        self._config = infection_monkey.config.WormConfiguration

    def get_host_fingerprint(self, host):
        """
        Returns elasticsearch metadata
        :param host:
        :return: Success/failure, data is saved in the host struct
        """
        urls = ['{}://{}:{}'.format(protocol, host.ip_addr, ES_PORT) for protocol in ['http', 'https']]
        for url in urls:
            try:
                with closing(requests.get(url, timeout=ES_HTTP_TIMEOUT, verify=False)) as req:
                    data = json.loads(req.text)
                    self.init_service(host.services, ES_SERVICE, ES_PORT)
                    host.services[ES_SERVICE]['cluster_name'] = data['cluster_name']
                    host.services[ES_SERVICE]['name'] = data['name']
                    host.services[ES_SERVICE]['version'] = data['version']['number']
                    host.services[ES_SERVICE]['tls'] = 'https' in url
                    return True
            except Timeout:
                pass
            except ConnectionError:  # Someone doesn't like us
                pass
            except KeyError:
                LOG.debug("Failed parsing the ElasticSearch JSON response")
        return False
