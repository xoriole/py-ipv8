from __future__ import absolute_import

import copy

default = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [
        {
            'alias': "anonymous id",
            'generation': u"medium",
            'file': u"ec_multichain.pem"
        }
    ],
    'logger': {
        'level': "DEBUG"
    },
    'walker_interval': 0.5,
    'overlays': [
        {
            'class': 'DiscoveryCommunity',
            'key': "anonymous id",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': -1,
                    'init': {
                        'timeout': 60.0
                    }
                },
                {
                    'strategy': "RandomChurn",
                    'peers': -1,
                    'init': {
                        'sample_size': 64,
                        'ping_interval': 10.0,
                        'inactive_time': 45.0,
                        'drop_time': 60.0
                    }
                },
                {
                    'strategy': "PeriodicSimilarity",
                    'peers': -1,
                    'init': {}
                }
            ],
            'initialize': {},
            'on_start': [
                ('resolve_dns_bootstrap_addresses', )
            ]
        }
    ]
}


def get_default_configuration():
    return copy.deepcopy(default)


__all__ = ['get_default_configuration']
