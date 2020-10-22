from binascii import unhexlify, hexlify
from base64 import b64encode

import geoip2.database
from aiohttp import web

from aiohttp_apispec import docs

from marshmallow.fields import Integer, String

from .base_endpoint import BaseEndpoint, HTTP_NOT_FOUND, Response
from .schema import BlockSchema, schema


class CrawlerEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding Crawler.
    """

    def __init__(self):
        super(CrawlerEndpoint, self).__init__()
        self.geoip = None

    def setup_routes(self):
        self.app.add_routes([web.get('/peers', self.get_peers),
                             web.get('/services', self.get_community_peers),
                             web.get('/geo', self.get_geo_users)])

    def initialize(self, session):
        super(CrawlerEndpoint, self).initialize(session)
        self.geoip = geoip2.database.Reader(session.configuration['crawler']['geodb'])

    @docs(
        tags=["Crawler"],
        summary="Return a list of all known peers.",
        responses={
            200: {
                "schema": schema(PeersResponse={
                    "peers": [schema(Peer={
                        "public_key": String
                    })]
                })
            }
        }
    )
    async def get_peers(self, request):
        network = self.session.network
        peer_list = network.verified_peers
        return Response({"peers": {
            b64encode(peer.mid).decode('utf-8'): {
                "public_key": b64encode(peer.public_key.key_to_bin()).decode('utf-8')
            }
            for peer in peer_list
        }})

    @docs(
        tags=["Crawler"],
        summary="Return a count of peers in a given service.",
        parameters=[{
            'in': 'query',
            'name': 'id',
            'description': 'Community id',
            'type': 'string',
            'required': False
        }],
        responses={
            200: {
                "schema": schema(BlockResponse={
                    "block": BlockSchema
                })
            }
        }
    )
    async def get_community_peers(self, request):
        network = self.session.network
        peer_list = network.verified_peers

        filter_cid = None
        if 'id' in request.query and request.query['id']:
            filter_cid = request.query['id']

        services_dict = {}
        for p in peer_list:
            for cid in network.get_services_for_peer(p):
                b64cid = b64encode(cid)
                hex_cid = str(hexlify(cid))
                print(f"cid: {cid}, b64: {b64cid}, hex: {hex_cid}")
                if filter_cid and filter_cid != hex_cid:
                    continue
                services_dict[hex_cid] = 1 + services_dict.get(hex_cid, 0)
        print(f"services: {services_dict}")
        return Response(services_dict)


    @docs(
        tags=["Crawler"],
        summary="Return a map of country and user count",
        responses={
            200: {
                "schema": schema(UsersResponse={
                    "geo": [schema(Country={
                        "country": String,
                        "count": Integer
                    })]
                })
            }
        }
    )
    async def get_geo_users(self, request):
        network = self.session.network
        peer_list = network.verified_peers
        countries_dict = {}
        for p in peer_list:
            print(f"checking address: {p.address[0]}, {type(p.address[0])}")
            country = self.geoip.country(p.address[0]).country.iso_code
            if country:
                countries_dict[country] = 1 + countries_dict.get(country, 0)
            else:
                countries_dict['?'] = 1 + countries_dict.get('?', 0)
        return Response(countries_dict)
