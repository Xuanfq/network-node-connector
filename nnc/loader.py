from nnc import config
from nnc.client import NodeClient
from nnc.server import NodeService
from nnc.auth import SSHAuthenticator


def new_client(conf: str = config.DEFAULT_CONF, **kwargs):
    cfgdict = config.load(conf=conf, section="common")
    cfgdict.update(kwargs)
    return NodeClient(**cfgdict)


def new_service(conf: str = config.DEFAULT_CONF, **kwargs):
    commoncfg = config.load(conf=conf, section="common")
    commoncfg.update(kwargs)
    authcfg = config.load(conf=conf, section="authentication")
    authcfg.update(kwargs)
    auth = SSHAuthenticator(**authcfg)
    return NodeService(authenticator=auth, **commoncfg)
