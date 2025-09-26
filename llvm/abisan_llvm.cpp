#include <algorithm> // for std::find
#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDirectives.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCParser/AsmLexer.h>
#include <llvm/MC/MCParser/MCAsmParser.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCSymbol.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/TargetParser/Host.h>
#include <unordered_set>
#include <vector>

using namespace llvm;

// TODO: Pull this from the appropriate LLVM headers.
namespace X86 {
MCRegister const EFLAGS = MCRegister::from(28);
MCRegister const RAX = MCRegister::from(51);
MCRegister const RBP = MCRegister::from(52);
MCRegister const RBX = MCRegister::from(53);
MCRegister const RCX = MCRegister::from(54);
MCRegister const RDI = MCRegister::from(55);
MCRegister const RDX = MCRegister::from(56);
MCRegister const RSI = MCRegister::from(60);
MCRegister const RSP = MCRegister::from(61);
MCRegister const R8 = MCRegister::from(119);
MCRegister const R9 = MCRegister::from(120);
MCRegister const R10 = MCRegister::from(121);
MCRegister const R11 = MCRegister::from(122);
MCRegister const R12 = MCRegister::from(123);
MCRegister const R13 = MCRegister::from(124);
MCRegister const R14 = MCRegister::from(125);
MCRegister const R15 = MCRegister::from(126);
}; // namespace X86

class ABISanStreamer : public MCStreamer {
    MCStreamer &underlying;
    MCInstrInfo const &instr_info;
    MCRegisterInfo const &register_info;
    MCSubtargetInfo const &subtarget_info;

    std::unordered_set<std::string> instrumented_function_names;

    unsigned get_taint_index(MCRegister const reg) {
        if (reg == X86::RAX) {
            return 0;
        }
        if (reg == X86::RBX) {
            return 1;
        }
        if (reg == X86::RCX) {
            return 2;
        }
        if (reg == X86::RDX) {
            return 3;
        }
        if (reg == X86::RDI) {
            return 4;
        }
        if (reg == X86::RSI) {
            return 5;
        }
        if (reg == X86::R8) {
            return 6;
        }
        if (reg == X86::R9) {
            return 7;
        }
        if (reg == X86::R10) {
            return 8;
        }
        if (reg == X86::R11) {
            return 9;
        }
        if (reg == X86::R12) {
            return 10;
        }
        if (reg == X86::R13) {
            return 11;
        }
        if (reg == X86::R14) {
            return 12;
        }
        if (reg == X86::R15) {
            return 13;
        }
        if (reg == X86::RBP) {
            return 14;
        }
        if (reg == X86::EFLAGS) {
            return 15;
        }
        outs() << "Couldn't find taint index for register ";
        print_register(reg);
        outs() << "\n";
        exit(1);
    }

    unsigned get_opcode(std::string const &mnemonic) {
        for (unsigned int i = 0; i < instr_info.getNumOpcodes(); i++) {
            if (instr_info.getName(i).lower() == mnemonic) {
                return i;
            }
        }
        outs() << "Couldn't find the opcode for " << mnemonic << "!\n";
        exit(1);
    }

    MCInst make_instruction(std::string const &mnemonic, std::vector<MCOperand> ops) {
        MCInst result;
        result.setOpcode(get_opcode(mnemonic));

        for (auto const &op : ops) {
            result.addOperand(op);
        }
        return result;
    }

    std::vector<MCRegister> get_written_registers(MCInst const &inst) {
        MCInstrDesc const &instr_desc = instr_info.get(inst.getOpcode());

        std::vector<MCRegister> result;
        for (unsigned i = 0; i < register_info.getNumRegs(); i++) {
            MCRegister const reg = MCRegister::from(i);
            if (instr_desc.hasDefOfPhysReg(inst, reg, register_info)) {
                result.push_back(reg);
            }
        }
        if (inst.getOpcode() == get_opcode("syscall")) {
            result.push_back(X86::RCX);
            result.push_back(X86::R11);
        }
        return result;
    }

    std::vector<MCRegister> get_used_registers(MCInst const &inst) {
        MCInstrDesc const &instr_desc = instr_info.get(inst.getOpcode());

        std::vector<MCRegister> result;
        for (unsigned i = 0; i < inst.getNumOperands(); i++) {
            auto const &operand = inst.getOperand(i);
            if (operand.isReg() && operand.getReg() != 0) {
                result.push_back(operand.getReg());
            }
        }
        auto const &implicit_uses = instr_desc.implicit_uses();
        auto const &implicit_defs = instr_desc.implicit_defs();
        result.insert(result.end(), implicit_uses.begin(), implicit_uses.end());
        result.insert(result.end(), implicit_defs.begin(), implicit_defs.end());
        if (inst.getOpcode() == get_opcode("syscall")) {
            result.push_back(X86::RCX); // written
            result.push_back(X86::R11); // written
            result.push_back(X86::RAX); // read
        }
        return result;
    }

    std::vector<MCRegister> get_read_registers(MCInst const &inst) {
        std::vector<MCRegister> result = get_used_registers(inst);
        std::vector<MCRegister> written_registers = get_written_registers(inst);
        for (auto const &written_register : written_registers) {
            auto the_find = std::find(result.begin(), result.end(), written_register);
            if (the_find != result.end()) {
                result.erase(the_find);
            }
        }

        std::vector<MCRegister> deduped_result;
        for (auto const &r1 : result) {
            bool dup = false;
            for (auto const &r2 : deduped_result) {
                if (r1 == r2) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                deduped_result.push_back(r1);
            }
        }
        return deduped_result;
    }

    char utoc(unsigned const u) {
        switch (u) {
        case 0x0:
            return '0';
        case 0x1:
            return '1';
        case 0x2:
            return '2';
        case 0x3:
            return '3';
        case 0x4:
            return '4';
        case 0x5:
            return '5';
        case 0x6:
            return '6';
        case 0x7:
            return '7';
        case 0x8:
            return '8';
        case 0x9:
            return '9';
        case 0xa:
            return 'a';
        case 0xb:
            return 'b';
        case 0xc:
            return 'c';
        case 0xd:
            return 'd';
        case 0xe:
            return 'e';
        case 0xf:
            return 'f';
        }
        outs() << "Invalid arg to utoc\n";
        exit(1);
    }

    void print_register(MCRegister const reg) {
        outs() << register_info.getName(reg) << " (" << reg << ") ";
    }

    void print_register_vector(std::vector<MCRegister> const regs) {
        for (auto const &reg : regs) {
            print_register(reg);
        }
    }

    std::string symbol_to_string(MCSymbol const *const symbol) {
        StringRef symbol_name_stringref = symbol->getName();
        std::string result;
        result.assign(symbol_name_stringref.data(), symbol_name_stringref.size());
        return result;
    }

  public:
    ABISanStreamer(MCStreamer &underlying, MCInstrInfo const &instr_info,
                   MCRegisterInfo const &register_info, MCSubtargetInfo const &subtarget_info)
        : MCStreamer(underlying.getContext()), underlying(underlying), instr_info(instr_info),
          register_info(register_info), subtarget_info(subtarget_info) {
    }

    void emitInstruction(MCInst const &inst, MCSubtargetInfo const &subtarget_info) override {
        underlying.emitInstruction(inst, subtarget_info);

        std::vector<MCRegister> written_registers = get_written_registers(inst);
        if (!written_registers.empty()) {
            outs() << "            # Writes: ";
            print_register_vector(written_registers);
            outs() << '\n';
        }

        std::vector<MCRegister> read_registers = get_read_registers(inst);
        if (!read_registers.empty()) {
            outs() << "            # Reads:  ";
            print_register_vector(read_registers);
            outs() << '\n';
        }
    }

    bool emitSymbolAttribute(MCSymbol *symbol, MCSymbolAttr attribute) override {
        bool const result = underlying.emitSymbolAttribute(symbol, attribute);

        if (attribute == MCSA_Global &&
            (!symbol->isInSection() ||
             symbol->getSection().hasInstructions())) { // .globl and has code and is in an executable
                                                        // section, or no section
            // Really this should be a preprocessing pass, but in practice,
            // people tend to declare .globl before the label.
            // TODO: fix this.
            instrumented_function_names.insert(symbol_to_string(symbol));
        }
        return result;
    }

    void emitCommonSymbol(MCSymbol *symbol, uint64_t size, Align alignment) override {
        underlying.emitCommonSymbol(symbol, size, alignment);
    }

    void emitZerofill(MCSection *section, MCSymbol *symbol = nullptr, uint64_t size = 0,
                      Align byte_alignment = Align(1), SMLoc loc = SMLoc()) override {
        underlying.emitZerofill(section, symbol, size, byte_alignment, loc);
    }

    void emitLabel(MCSymbol *symbol, SMLoc loc = SMLoc()) override {
        // TODO: Use the underlying output stream
        // or use underlying.emitLabel, but this was segfaulting for some reason :(
        outs() << symbol->getName() << ":\n";
        for (auto const &instrumented_function_name : instrumented_function_names) {
            if (symbol_to_string(symbol) == instrumented_function_name) {
                outs() << "\tcall abisan_function_entry\n";
            } else {
                errs() << symbol_to_string(symbol) << " != " << instrumented_function_name << "\n";
            }
        }
    }

    void emitBytes(StringRef str) override {
        underlying.emitBytes(str);
    }

    void switchSection(MCSection *section, uint32_t subsection = 0) override {
        underlying.switchSection(section, subsection);
    }
};

int main(int argc, char **argv) {
    if (argc < 2) {
        outs() << "Usage: " << argv[0] << " <file.s>\n";
        exit(1);
    }

    InitializeAllTargetInfos();
    InitializeAllTargetMCs();
    InitializeAllAsmParsers();

    std::string error;
    std::string triple_name = sys::getDefaultTargetTriple();
    Target const *target = TargetRegistry::lookupTarget(triple_name, error);

    if (!target) {
        outs() << "Failed to lookup target: " << error << "\n";
        exit(1);
    }

    MCTargetOptions options;
    std::unique_ptr<MCRegisterInfo> register_info(target->createMCRegInfo(triple_name));
    std::unique_ptr<MCAsmInfo> asm_info(target->createMCAsmInfo(*register_info, triple_name, options));
    std::unique_ptr<MCSubtargetInfo> subtarget_info(target->createMCSubtargetInfo(triple_name, "", ""));
    std::unique_ptr<MCInstrInfo> instr_info(target->createMCInstrInfo());
    llvm::SourceMgr src_mgr;

    auto buffer_or_error = MemoryBuffer::getFile(argv[1]);
    if (!buffer_or_error) {
        outs() << "Error reading file: " << argv[1] << "\n";
        exit(1);
    }
    src_mgr.AddNewSourceBuffer(std::move(*buffer_or_error), SMLoc());

    MCContext ctx(Triple(triple_name), asm_info.get(), register_info.get(), subtarget_info.get(),
                  &src_mgr);
    auto object_file_info = std::make_unique<MCObjectFileInfo>();
    object_file_info->initMCObjectFileInfo(ctx, false);
    ctx.setObjectFileInfo(object_file_info.get());

    std::unique_ptr<MCAsmBackend> asm_backend(
        target->createMCAsmBackend(*subtarget_info, *register_info, options));
    auto base_streamer(target->createAsmStreamer(
        ctx, std::make_unique<formatted_raw_ostream>(outs()),
        target->createMCInstPrinter(Triple(triple_name), asm_info->getAssemblerDialect(), *asm_info,
                                    *instr_info, *register_info),
        std::unique_ptr<MCCodeEmitter>(), std::move(asm_backend)));
    auto streamer =
        std::make_unique<ABISanStreamer>(*base_streamer, *instr_info, *register_info, *subtarget_info);
    streamer->initSections(false, *subtarget_info);

    auto parser(createMCAsmParser(src_mgr, ctx, *streamer, *asm_info));
    auto target_parser(target->createMCAsmParser(*subtarget_info, *parser, *instr_info, options));

    if (!target_parser) {
        outs() << "No target-specific asm parser for " << triple_name << "\n";
        exit(1);
    }

    parser->setTargetParser(*target_parser);
    if (parser->Run(false)) {
        outs() << "Failed to parse assembly.\n";
        exit(1);
    }
}
