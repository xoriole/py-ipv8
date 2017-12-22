from __future__ import absolute_import

from .base_endpoint import BaseEndpoint
from .crawler_geo_endpoint import CrawlerGeoEndpoint
from .crawler_peers_endpoint import CrawlerPeersEndpoint
from .network_endpoint import NetworkEndpoint
from .service_endpoint import ServiceEndpoint


class RootEndpoint(BaseEndpoint):
    """
    The root endpoint of the HTTP API is the root resource in the request tree.
    It will dispatch requests regarding torrents, channels, settings etc to the right child endpoint.
    """

    def __init__(self, session):
        """
        During the initialization of the REST API, we only start the event sockets and the state endpoint.
        We enable the other endpoints after completing the starting procedure.
        """
        super(RootEndpoint, self).__init__()
        self.session = session

        self.putChild("crawler_geo", CrawlerGeoEndpoint(session))
        self.putChild("crawler_peers", CrawlerPeersEndpoint(session))
        self.putChild("network", NetworkEndpoint(session))
        self.putChild("service", ServiceEndpoint(session))

