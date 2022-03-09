import angr
from angr.procedures.stubs.format_parser import FormatParser

import utils

import logging

log = logging.getLogger(__name__)

class SimProcedureCall:
    def __init__(self, p, rd_at_call, simproc, raise_if_format_parser=True):
        if isinstance(simproc, FormatParser) and raise_if_format_parser:
            raise TypeError("Use FormatParserCall instead or set raise_if_format_parser=False")

        self.p = p
        self.rd_at_call = rd_at_call
        self.simproc = simproc
        self._num_args=None


    @property
    def num_args(self):
        if not self._num_args is None:
            return self._num_args

        if not self.simproc.ARGS_MISMATCH:
            self._num_args = self.simproc.num_args
        else:
            f = self.p.kb.functions.get(self.simproc.display_name)
            cc = None
            if f:
                cc = f.calling_convention
                if not cc:
                    cfg = self.p.kb.cfgs["CFGFast"]
                    cc_result = self.p.analyses.CallingConvention(f, cfg, analyze_callsites=True)
                    cc = cc_result.cc

            if cc and cc.args:
                self._num_args = len(cc.args)
            else:
                self._num_args = 4
                log.warning("ARGS_MISMATCH: using %d" % self._num_args)

        return self._num_args


    def enumerate_constant_args(self):
        for arg_ix, arg_def in enumerate(self.get_arg_defs()):
            arg_data = arg_def.data.get_first_element()
            if isinstance(arg_data, int):
                yield (arg_ix, arg_data)

    def get_constant_args(self):
        for arg_def in self.get_arg_defs():
            arg_data = arg_def.data.get_first_element()
            if isinstance(arg_data, int):
                yield arg_data


    def get_arg_defs(self):
        for arg_ix in range(self.num_args):
            yield self.get_arg_def(arg_ix)


    def get_arg_def(self, arg_ix):
        if arg_ix >= self.num_args:
            raise ValueError("arg_ix > num_args")

        cc = angr.DEFAULT_CC[self.p.arch.name]
        n_arg_regs = len(cc.ARG_REGS)

        if arg_ix < n_arg_regs:
            reg_offset = utils.get_arg_reg_offset(self.p, arg_ix)
            arg_defs = self.rd_at_call.register_definitions.get_variables_by_offset(reg_offset)
        else:
            current_sp_offset = self.rd_at_call.get_sp()
            stack_offset = (arg_ix - n_arg_regs) * self.p.arch.bytes + current_sp_offset.offset
            arg_defs = self.rd_at_call.stack_definitions.get_variables_by_offset(stack_offset)

        return next(iter(arg_defs))


class FormatParserCall(SimProcedureCall):
    def __init__(self, p, rd_at_call, simproc):
        super(FormatParserCall, self).__init__(p, rd_at_call, simproc, False)
        self._num_args = 8
        self.fmt_str_arg_ix = None
        self.fmt_str = None

        for arg_ix, const_arg in self.enumerate_constant_args():
            fmt_str = utils.load_string_from_memory(self.p, const_arg)
            if not fmt_str:
                continue

            n_fmt_args = fmt_str.count("%") - fmt_str.count("%%") * 2

            if n_fmt_args > 0:
                self._num_args = 4 + n_fmt_args
                self.fmt_str_arg_ix = arg_ix
                self.fmt_str = fmt_str
                break
        