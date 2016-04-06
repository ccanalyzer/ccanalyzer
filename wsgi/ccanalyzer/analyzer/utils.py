import os
import math


class Filesystem(object):
    @staticmethod
    def hsize_iec(size):
        """ IEC-I (https://gist.github.com/koaeH/162095ed2c3090031874) """
        base = math.log(size) / math.log(1024)
        suffix = ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB')
        return "%d %s" % (math.pow(1024, base-math.floor(base)), suffix[int(math.floor(base))])
