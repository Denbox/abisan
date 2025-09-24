#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCParser/AsmLexer.h>
#include <llvm/MC/MCParser/MCAsmParser.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/TargetParser/Host.h>

using namespace llvm;

class ABISanStreamer : public MCStreamer {
    MCStreamer &underlying;
    MCInstrInfo const &mcii;

  public:
    ABISanStreamer(MCStreamer &underlying, MCInstrInfo const &mcii)
        : MCStreamer(underlying.getContext()), underlying(underlying),
          mcii(mcii) {
    }

    unsigned int get_opcode(std::string const &mnemonic) {
        for (unsigned int i = 0; i < mcii.getNumOpcodes(); i++) {
            errs() << mcii.getName(i) << "\n";
            if (mcii.getName(i).lower() == mnemonic) {
                return i;
            }
        }
        errs() << "Couldn't find the opcode for " << mnemonic << "!\n";
        exit(-1);
    }

    MCInst ins(std::string const &mnemonic, std::vector<MCOperand> ops) {
        MCInst result;
        result.setOpcode(get_opcode(mnemonic));
        for (auto const &op : ops) {
            result.addOperand(op);
        }
        return result;
    }

    void emitInstruction(MCInst const &inst,
                         MCSubtargetInfo const &sti) override {
        MCInstrDesc const &desc = mcii.get(inst.getOpcode());
        if (desc.isCall()) {
            underlying.emitInstruction(ins("push64r", {}), sti);
        }
        underlying.emitInstruction(inst, sti);
    }

    bool emitSymbolAttribute(MCSymbol *symbol,
                             MCSymbolAttr attribute) override {
        return underlying.emitSymbolAttribute(symbol, attribute);
    }

    void emitCommonSymbol(MCSymbol *symbol, uint64_t size,
                          Align alignment) override {
        underlying.emitCommonSymbol(symbol, size, alignment);
    }

    void emitZerofill(MCSection *section, MCSymbol *symbol = nullptr,
                      uint64_t size = 0, Align byte_alignment = Align(1),
                      SMLoc loc = SMLoc()) override {
        underlying.emitZerofill(section, symbol, size, byte_alignment, loc);
    }
};

int main(int argc, char **argv) {
    if (argc < 2) {
        errs() << "Usage: " << argv[0] << " <file.s>\n";
        return 1;
    }

    InitializeAllTargetInfos();
    InitializeAllTargetMCs();
    InitializeAllAsmParsers();

    std::string error;
    std::string triple_name = sys::getDefaultTargetTriple();
    Target const *target = TargetRegistry::lookupTarget(triple_name, error);

    if (!target) {
        errs() << "Failed to lookup target: " << error << "\n";
        return 1;
    }

    MCTargetOptions MCOptions;
    std::unique_ptr<MCRegisterInfo> mri(target->createMCRegInfo(triple_name));
    std::unique_ptr<MCAsmInfo> mai(
        target->createMCAsmInfo(*mri, triple_name, MCOptions));
    std::unique_ptr<MCSubtargetInfo> sti(
        target->createMCSubtargetInfo(triple_name, "", ""));
    std::unique_ptr<MCInstrInfo> mcii(target->createMCInstrInfo());
    llvm::SourceMgr src_mgr;

    auto buffer_or_error = MemoryBuffer::getFile(argv[1]);
    if (!buffer_or_error) {
        errs() << "Error reading file: " << argv[1] << "\n";
        return 1;
    }
    src_mgr.AddNewSourceBuffer(std::move(*buffer_or_error), SMLoc());

    MCContext ctx(Triple(triple_name), mai.get(), mri.get(), sti.get(),
                  &src_mgr);
    auto mofi = std::make_unique<MCObjectFileInfo>();
    mofi->initMCObjectFileInfo(ctx, false);
    ctx.setObjectFileInfo(mofi.get());

    auto fos = std::make_unique<formatted_raw_ostream>(outs());
    auto *ip = target->createMCInstPrinter(
        Triple(triple_name), mai->getAssemblerDialect(), *mai, *mcii, *mri);
    std::unique_ptr<MCAsmBackend> tab(
        target->createMCAsmBackend(*sti, *mri, MCOptions));
    auto base_streamer(target->createAsmStreamer(
        ctx, std::move(fos), ip, std::unique_ptr<MCCodeEmitter>(),
        std::move(tab)));
    auto streamer = std::make_unique<ABISanStreamer>(*base_streamer, *mcii);
    streamer->initSections(false, *sti);

    auto parser(createMCAsmParser(src_mgr, ctx, *streamer, *mai));
    auto target_parser(target->createMCAsmParser(*sti, *parser, *mcii, MCOptions));

    if (!target_parser) {
        errs() << "No target-specific asm parser for " << triple_name << "\n";
        return 1;
    }

    parser->setTargetParser(*target_parser);
    if (parser->Run(false)) {
        errs() << "Failed to parse assembly.\n";
        return 1;
    }

    return 0;
}
