import configparser
import ast

DEFAULT_CONF = "/etc/nnc/nnc.conf"


def load(conf: str = DEFAULT_CONF, section: str = "defaults"):
    parser = configparser.ConfigParser()
    parser.read(conf, encoding="utf-8")
    cfgdict = dict(parser.items(section=section))
    for k, v in cfgdict.items():
        if v.lower() == "true" or v.lower() == "false":
            cfgdict[k] = bool(v)
            continue
        try:
            cfgdict[k] = ast.literal_eval(v)
            continue
        except Exception as e:
            print(e)
            pass
    return cfgdict
