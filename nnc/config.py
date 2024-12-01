import configparser
import ast

DEFAULT_CONF = "/etc/nnc/nnc.conf"


def load(conf: str = DEFAULT_CONF, section: str = "common"):
    parser = configparser.ConfigParser()
    parser.read(conf, encoding="utf-8")
    try:
        cfgdict = dict(parser.items(section=section))
    except Exception as e:
        cfgdict = {}
    for k, v in cfgdict.items():
        if v.lower() == "true" or v.lower() == "false":
            cfgdict[k] = bool(v)
            continue
        try:
            cfgdict[k] = ast.literal_eval(v)
            continue
        except Exception as e:
            pass
    return cfgdict
