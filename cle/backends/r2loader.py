from ..errors import CLEError
from . import Backend

import r2pipe
import struct
# try:
#     # r2pipe.open ('http://cloud.radare.org/cmd/', doStuff);
#     r2p = r2pipe
# except:
# r2p = None


import logging
l = logging.getLogger("cle.r2loader")
import archinfo

__all__ = ('r2Loader',)


class r2Loader(Backend):
    """
    This is a backend that uses radare2 (via r2pipe). Untested and experimental, use at your own risk.
    """
    def __init__(self, binary, *args, **kwargs):
        """
        :param binary: The file/binary to load.
        :param custom_arch: The arch of the binary (this shouldn't be needed... but it is right now.)
        """

        super(r2Loader, self).__init__(binary, *args, **kwargs)

        if self.binary is None:
            raise CLEError("You need to give a file.")

        self.set_arch(archinfo.arch_from_id("EM_386", 'le', '32'))  # TODO: Get this info from r2.

        l.debug("Starting r2pipe..")

        r2p = r2pipe.open(self.binary)
        l.debug("r2pipe opened!")
        r2p.cmd('aaa')
        l.debug("Running aaa")

        self._r2o = {}  # This is where the output of radare2 will go.

        l.debug("Starting command loop...")

        '''This is for reference.
        |Usage: i Get info from opened file (see rabin2's manpage)
        | Output mode:
        | '*'                Output in radare commands
        | 'j'                Output in json
        | 'q'                Simple quiet output
        | Actions:
        | i|ij               Show info of current file (in JSON)
        | iA                 List archs
        | ia                 Show all info (imports, exports, sections..)
        | ib                 Reload the current buffer for setting of the bin (use once only)
        | ic                 List classes, methods and fields
        | iC                 Show signature info (entitlements, ...)
        | id                 Debug information (source lines)
        | iD lang sym        demangle symbolname for given language
        | ie                 Entrypoint
        | iE                 Exports (global symbols)
        | ih                 Headers (alias for iH)
        | iHH                Verbose Headers in raw text
        | ii                 Imports
        | iI                 Binary info
        | ik [query]         Key-value database from RBinObject
        | il                 Libraries
        | iL                 List all RBin plugins loaded
        | im                 Show info about predefined memory allocation
        | iM                 Show main address
        | io [file]          Load info from file (or last opened) use bin.baddr
        | ir|iR              Relocs
        | is                 Symbols
        | iS [entropy,sha1]  Sections (choose which hash algorithm to use)
        | iV                 Display file version info
        | iz                 Strings in data sections
        | izz                Search for Strings in the whole binary
        | iZ                 Guess size of binary program
        '''
        commands = ['i', 'iA', 'ie', 'iE', 'ih', 'ii', 'il', 'iM', 'ir', 'is', 'iS', 'izz']

        for command in commands:
            command_j = command + 'j'
            l.debug(command_j)
            self._r2o[command] = r2p.cmdj(command_j)
            l.debug(self._r2o[command])

        self._r2o['pc'] = r2p.cmdj('pcj $s')

        r2p.quit()

        l.debug("Done with r2pipe.")

        # self.memory = "" #.add_backer(0, "y")

        rawdata = self._r2o['pc']
        packed = struct.pack("%dB" % (len(rawdata)), *rawdata)

        # self.memory.add_backer(0, packed)

        self._r2o['']

        # TODO: Everything

        elf.got_begin = None
        self.got_end = None
        self.raw_imports = {}
        self.current_module_name = None

        self.imports = {} # self._get_imports()
        self.resolved_imports = {}
        self.linking = {} # self._get_linking_type()

    @property
    def entry(self):
        return self._r2o['ie'][0]['vaddr']
        # if self._custom_entry_point is not None:
    #         return self._custom_entry_point + self.rebase_addr
    #     return None # self.ida.idc.BeginEA() + self.rebase_addr

    supported_filetypes = ['elf', 'pe', 'mach-o', 'unknown']

    # @property
    # def plt(self):
    #     # I know there's a way to do this but BOY do I not want to do it right now
    #     return {}
    #
    # @property
    # def reverse_plt(self):
    #     return {}
    #
    # @staticmethod
    # def get_call_stub_addr(name): # pylint: disable=unused-argument
    #     return None
    #
    @property
    def is_ppc64_abiv1(self):
        # IDA 6.9 segfaults when loading ppc64 abiv1 binaries so....
        return False

from ..loader import Loader
