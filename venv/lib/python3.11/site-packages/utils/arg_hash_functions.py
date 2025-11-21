from collections import OrderedDict
import flatdict
import re

ENDPOINTS_LIST = [
    '/analyses',
    '/analysiscategories',
    '/analysisruleplugins',
    '/analysisrules',
    '/analysistemplates',
    '/assetdatabases',
    '/assetservers',
    '/attributecategories',
    '/attributes',
    '/attributetemplates',
    '/attributetraits',
    '/batch',
    '/calculation',
    '/channels',
    '/data', #TODO: check and confirm
    '/dataservers',
    '/elementcategories',
    '/elements',
    '/elementtemplates',
    '/enumerationsets',
    '/eventframes',
    '/points',
    '/securityidentities',
    '/securitymappings',
    '/streams',
    '/streamsets',
    '/system',
    '/tablecategories',
    '/tables',
    '/timeruleplugins',
    '/timerules',
    '/unitclasses',
    '/units'
]

ENDPOINTS_REGEX = "({})".format('|'.join(ENDPOINTS_LIST))

send_request_args_hash_endpoints_regex = '(?!=.*){}.*'.format(ENDPOINTS_REGEX)

def send_request_args_hash(*args, **kwargs):

    _kwargs = OrderedDict(sorted(flatdict.FlatDict(kwargs).items()))

    path = re.findall(send_request_args_hash_endpoints_regex, args[1])[0]

    method = args[2]

    return "{}{}{}".format(path, method, kwargs)