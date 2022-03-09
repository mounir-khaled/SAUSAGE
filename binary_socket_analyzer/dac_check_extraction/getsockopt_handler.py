import logging

from angr.engines.light import RegisterOffset
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.knowledge_plugins.key_definitions.undefined import Undefined

from generic_function_handler import GenericFunctionHandler

log = logging.getLogger(__name__)

class CredData(Undefined):
    def __init__(self, name):
        self.name = name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, CredData):
            return self.name == other.name
        else:
            return False

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

class GetsockoptHandler(GenericFunctionHandler):
    def __init__(self):
        super(GetsockoptHandler, self).__init__(default_n_args=4, tag_parameters=True)
    
    def _initialize_handlers(self):
        self.handle_getsockopt = self._create_handler(self._handle_getsockopt, [2, 3])

    def _handle_getsockopt(self,
                           state,
                           codeloc,
                           optname_dataset:'DataSet',
                           optval_dataset:'DataSet'):

        optname = None
        if 17 in optname_dataset:
            optname = "SO_PEERCRED"
        elif 31 in optname_dataset:
            optname = "SO_PEERSEC"
        else:
            optname_int = optname_dataset.get_first_element()
            log.warning("optname %d is not handled" % optname_int)

        if optname == "SO_PEERCRED":
            cred_sp_offsets = set(sp_offset for sp_offset in optval_dataset if isinstance(sp_offset, RegisterOffset))
            pid_addr_set = cred_sp_offsets.copy()
            uid_addr_set = set(sp_offset + 4 for sp_offset in cred_sp_offsets)
            gid_addr_set = set(sp_offset + 8 for sp_offset in cred_sp_offsets)

            pid_dataset = DataSet({CredData("pid")}, 32)
            uid_dataset = DataSet({CredData("uid")}, 32)
            gid_dataset = DataSet({CredData("gid")}, 32)

            self._store_dataset(state, codeloc, pid_addr_set, pid_dataset)
            self._store_dataset(state, codeloc, uid_addr_set, uid_dataset)
            self._store_dataset(state, codeloc, gid_addr_set, gid_dataset)

        elif optname == "SO_PEERSEC": # SO_PEERSEC
            log.info("SO_PEERSEC")
            pass

        return False, state

