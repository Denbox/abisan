//===-- llvm-mc-assemble-fuzzer.cpp - Fuzzer for the MC layer -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

// Compile with:
// clang llvm-mc-assembler.cpp $(llvm-config --cxxflags --ldflags --libs all) $(llvm-config --system-libs) -L/usr/lib64 -lstdc++
#include "llvm-c/Target.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/AsmLexer.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/SubtargetFeature.h"
#include <fstream>
#include <sstream>
#include <iostream>
using namespace llvm;

static mc::RegisterMCTargetOptionsFlags MOF;

static cl::opt<std::string>
InputFilename("file", cl::desc("*.s file to be assembled"), cl::Required);

static cl::opt<std::string>
    TripleName("triple", cl::desc("Target triple to assemble for, "
                                  "see -version for available targets"));

static cl::opt<std::string>
    MCPU("mcpu",
         cl::desc("Target a specific cpu type (-mcpu=help for details)"),
         cl::value_desc("cpu-name"), cl::init(""));

// This is useful for variable-length instruction sets.
static cl::opt<unsigned> InsnLimit(
    "insn-limit",
    cl::desc("Limit the number of instructions to process (0 for no limit)"),
    cl::value_desc("count"), cl::init(0));

static cl::list<std::string>
    MAttrs("mattr", cl::CommaSeparated,
           cl::desc("Target specific attributes (-mattr=help for details)"),
           cl::value_desc("a1,+a2,-a3,..."));
// The feature string derived from -mattr's values.
std::string FeaturesStr;

static std::vector<char *> ModifiedArgv;

class LLVMInputBuffer : public MemoryBuffer
{
  public:
    LLVMInputBuffer(const uint8_t *data_, size_t size_)
      : Data(reinterpret_cast<const char *>(data_)),
        Size(size_) {
        init(Data, Data+Size, false);
      }


    virtual BufferKind getBufferKind() const {
      return MemoryBuffer_Malloc; // it's not disk-backed so I think that's
                                  // the intent ... though AFAIK it
                                  // probably came from an mmap or sbrk
    }

  private:
    const char *Data;
    size_t Size;
};


static int AssembleInput(const char *ProgName, const Target *TheTarget,
                         SourceMgr &SrcMgr, MCContext &Ctx, MCStreamer &Str,
                         MCAsmInfo &MAI, MCSubtargetInfo &STI,
                         MCInstrInfo &MCII, MCTargetOptions &MCOptions) {
  static const bool NoInitialTextSection = false;

  std::unique_ptr<MCAsmParser> Parser(
    createMCAsmParser(SrcMgr, Ctx, Str, MAI));

  std::unique_ptr<MCTargetAsmParser> TAP(
    TheTarget->createMCAsmParser(STI, *Parser, MCII, MCOptions));

  if (!TAP) {
    errs() << ProgName
           << ": error: this target '" << TripleName
           << "', does not support assembly parsing.\n";
    abort();
  }

  Parser->setTargetParser(*TAP);

  return Parser->Run(NoInitialTextSection);
}

bool FakeArchMatch(llvm::Triple::ArchType Arch) {
    return true;
}


int AssembleOneInput(const uint8_t *Data, size_t Size) {
  Triple TheTriple(Triple::normalize(TripleName));

  SourceMgr SrcMgr;

  std::unique_ptr<MemoryBuffer> BufferPtr(new LLVMInputBuffer(Data, Size));

  // Tell SrcMgr about this buffer, which is what the parser will pick up.
  SrcMgr.AddNewSourceBuffer(std::move(BufferPtr), SMLoc());

  static const std::vector<std::string> NoIncludeDirs;
  SrcMgr.setIncludeDirs(NoIncludeDirs);

  static std::string ArchName;
  std::string Error;

  /*
    XXX
    Attempted to add *something* to the registry but it appears that nothing has been added
   */
  Target tempTarget;
  TargetRegistry::RegisterTarget(tempTarget,/* Name */ "x86_64-pc-linux-gnu", "ShortDesc", "BackendName", &FakeArchMatch, /* HasJIT */ false);

  std::cout << "Targets:" << std::endl;
  for (auto const &target : TargetRegistry::targets()) {
	  std::cout << "Target: " << target.getName() << std::endl;
  }
  std::cout << "Done with targets:" << std::endl;

  const Target *TheTarget = TargetRegistry::lookupTarget(ArchName, TheTriple,
      Error);
  if (ArchName.length() < 1){
    errs() << "SMALL " << TripleName << "\n";
  }
  if (!TheTarget) {
    errs() << "error: this target '" << TheTriple.normalize()
           << "/" << ArchName << "', was not found: '" << Error << "'\n";

    abort();
  }

  std::unique_ptr<MCRegisterInfo> MRI(TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    errs() << "Unable to create target register info!";
    abort();
  }

  MCTargetOptions MCOptions = mc::InitMCTargetOptionsFromFlags();
  std::unique_ptr<MCAsmInfo> MAI(
      TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
  if (!MAI) {
    errs() << "Unable to create target asm info!";
    abort();
  }

  std::unique_ptr<MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, FeaturesStr));

  MCContext Ctx(TheTriple, MAI.get(), MRI.get(), STI.get(), &SrcMgr);
  std::unique_ptr<MCObjectFileInfo> MOFI(
      TheTarget->createMCObjectFileInfo(Ctx, /*PIC=*/false));
  Ctx.setObjectFileInfo(MOFI.get());

  const unsigned OutputAsmVariant = 0;
  std::unique_ptr<MCInstrInfo> MCII(TheTarget->createMCInstrInfo());
  MCInstPrinter *IP = TheTarget->createMCInstPrinter(Triple(TripleName), OutputAsmVariant,
      *MAI, *MCII, *MRI);
  if (!IP) {
    errs()
      << "error: unable to create instruction printer for target triple '"
      << TheTriple.normalize() << "' with assembly variant "
      << OutputAsmVariant << ".\n";

    abort();
  }

  std::unique_ptr<MCCodeEmitter> CE = nullptr;
  std::unique_ptr<MCAsmBackend> MAB = nullptr;

  std::string OutputString;
  raw_string_ostream Out(OutputString);
  auto FOut = std::make_unique<formatted_raw_ostream>(Out);

  std::unique_ptr<MCStreamer> Str;


  Str.reset(TheTarget->createAsmStreamer(Ctx, std::move(FOut), IP,
                                           std::move(CE), std::move(MAB)));
  
  const int Res = AssembleInput(/* Prog Name */ "llvm-mc-assembler", TheTarget, SrcMgr, Ctx, *Str, *MAI, *STI,
      *MCII, MCOptions);

  (void) Res;

  return 0;
}

int main(int argc, char **argv) {
  cl::ParseCommandLineOptions(argc, argv, "Altered version of llvm's assemble-fuzzer\n");
  
  if (argc < 2 || argc > 3) {
    std::cout << "Usage: " << " -triple=$(gcc -dumpmachine) -file=filename" << std::endl;
    return 1;
  }
  std::ifstream t(InputFilename);
  std::stringstream buffer;
  buffer << t.rdbuf();

  return AssembleOneInput(reinterpret_cast<const uint8_t*>(buffer.str().data()), buffer.str().size());
}
