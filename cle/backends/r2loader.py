from ..errors import CLEError
from . import Backend

import r2pipe

try:
    # r2pipe.open ('http://cloud.radare.org/cmd/', doStuff);
    r2p = r2pipe
except:
    r2p = None


import logging
l = logging.getLogger("cle.r2loader")

# def spawn(bv):
#
#     r2p.cmd('aaa')
#     r2functions = r2p.cmdj('aflj')
#     r2p.quit()
#
#     for r2function in r2functions:
#         bv.add_function(bv.platform, r2function['offset'])  # should do r2function['name'] as well


class r2Loader(Backend):
    def __init__(self, binary, custom_arch=None, *args, **kwargs):

        if custom_arch is None:
            raise CLEError("Must specify custom_arch when loading r2test!")


        super(r2Loader, self).__init__(binary, custom_arch=None, *args, **kwargs)

        if self.binary is None:
            raise CLEError("File streaming isn't done yet.")

        l.debug("yolo")

        try:
            print "yep"
            # r2p = r2pipe.open(self.binary)
        except:
            raise CLEError("Opening r2pipe failed.")

    supported_filetypes = ['elf', 'pe', 'mach-o', 'unknown']