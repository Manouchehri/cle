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

__all__ = ('r2Loader',)

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

        # for segaddress in Segments


        self.memory = "" #.add_backer(0, "y")


        self.got_begin = None
        self.got_end = None
        self.raw_imports = {}
        self.current_module_name = None

        self.imports = {} # self._get_imports()
        self.resolved_imports = {}
        self.linking = {} # self._get_linking_type()

    @property
    def entry(self):
        if self._custom_entry_point is not None:
            return self._custom_entry_point + self.rebase_addr
        return None # self.ida.idc.BeginEA() + self.rebase_addr

    supported_filetypes = ['elf', 'pe', 'mach-o', 'unknown']

    @property
    def plt(self):
        # I know there's a way to do this but BOY do I not want to do it right now
        return {}

    @property
    def reverse_plt(self):
        return {}

    @staticmethod
    def get_call_stub_addr(name): # pylint: disable=unused-argument
        return None

    @property
    def is_ppc64_abiv1(self):
        # IDA 6.9 segfaults when loading ppc64 abiv1 binaries so....
        return False

from ..loader import Loader
