package mdaas

type TargetOS string

const TargetOSAix = TargetOS(`aix`)
const TargetOSAndroid = TargetOS(`android`)
const TargetOSDarwin = TargetOS(`darwin`)
const TargetOSDragonfly = TargetOS(`dragonfly`)
const TargetOSFreebsd = TargetOS(`freebsd`)
const TargetOSHurd = TargetOS(`hurd`)
const TargetOSIllumos = TargetOS(`illumos`)
const TargetOSIos = TargetOS(`ios`)
const TargetOSJs = TargetOS(`js`)
const TargetOSLinux = TargetOS(`linux`)
const TargetOSNetbsd = TargetOS(`netbsd`)
const TargetOSOpenbsd = TargetOS(`openbsd`)
const TargetOSPlan9 = TargetOS(`plan9`)
const TargetOSSolaris = TargetOS(`solaris`)
const TargetOSWasip1 = TargetOS(`wasip1`)
const TargetOSWindows = TargetOS(`windows`)
const TargetOSZos = TargetOS(`zos`)
const TargetOSUnknown = TargetOS(`unknown`)

var TargetOSMap = map[string]TargetOS{
	string(TargetOSAix):       TargetOSAix,
	string(TargetOSAndroid):   TargetOSAndroid,
	string(TargetOSDarwin):    TargetOSDarwin,
	string(TargetOSDragonfly): TargetOSDragonfly,
	string(TargetOSFreebsd):   TargetOSFreebsd,
	string(TargetOSHurd):      TargetOSHurd,
	string(TargetOSIllumos):   TargetOSIllumos,
	string(TargetOSIos):       TargetOSIos,
	string(TargetOSJs):        TargetOSJs,
	string(TargetOSLinux):     TargetOSLinux,
	string(TargetOSNetbsd):    TargetOSNetbsd,
	string(TargetOSOpenbsd):   TargetOSOpenbsd,
	string(TargetOSPlan9):     TargetOSPlan9,
	string(TargetOSSolaris):   TargetOSSolaris,
	string(TargetOSWasip1):    TargetOSWasip1,
	string(TargetOSWindows):   TargetOSWindows,
	string(TargetOSZos):       TargetOSZos,
	//string(TargetOSUnknown):   TargetOSUnknown,
}

type TargetArch string

const TargetArch386 = TargetArch(`386`)
const TargetArchAmd64 = TargetArch(`amd64`)
const TargetArchArm64be = TargetArch(`arm64be`)
const TargetArchArm64 = TargetArch(`arm64`)
const TargetArchArmbe = TargetArch(`armbe`)
const TargetArchArm = TargetArch(`arm`)
const TargetArchLoong64 = TargetArch(`loong64`)
const TargetArchMips64 = TargetArch(`mips64`)
const TargetArchMips64le = TargetArch(`mips64le`)
const TargetArchMips64p32 = TargetArch(`mips64p32`)
const TargetArchMips64p32le = TargetArch(`mips64p32le`)
const TargetArchMips = TargetArch(`mips`)
const TargetArchMipsle = TargetArch(`mipsle`)
const TargetArchPpc64 = TargetArch(`ppc64`)
const TargetArchPpc64le = TargetArch(`ppc64le`)
const TargetArchPpc = TargetArch(`ppc`)
const TargetArchRiscv64 = TargetArch(`riscv64`)
const TargetArchRiscv = TargetArch(`riscv`)
const TargetArchS390 = TargetArch(`s390`)
const TargetArchS390x = TargetArch(`s390x`)
const TargetArchSparc64 = TargetArch(`sparc64`)
const TargetArchSparc = TargetArch(`sparc`)
const TargetArchWasm = TargetArch(`wasm`)
const TargetArchUnknown = TargetArch(`unknown`)

var TargetArchMap = map[string]TargetArch{
	string(TargetArch386):         TargetArch386,
	string(TargetArchAmd64):       TargetArchAmd64,
	string(TargetArchArm64be):     TargetArchArm64be,
	string(TargetArchArm64):       TargetArchArm64,
	string(TargetArchArmbe):       TargetArchArmbe,
	string(TargetArchArm):         TargetArchArm,
	string(TargetArchLoong64):     TargetArchLoong64,
	string(TargetArchMips64):      TargetArchMips64,
	string(TargetArchMips64le):    TargetArchMips64le,
	string(TargetArchMips64p32):   TargetArchMips64p32,
	string(TargetArchMips64p32le): TargetArchMips64p32le,
	string(TargetArchMips):        TargetArchMips,
	string(TargetArchMipsle):      TargetArchMipsle,
	string(TargetArchPpc64):       TargetArchPpc64,
	string(TargetArchPpc64le):     TargetArchPpc64le,
	string(TargetArchPpc):         TargetArchPpc,
	string(TargetArchRiscv64):     TargetArchRiscv64,
	string(TargetArchRiscv):       TargetArchRiscv,
	string(TargetArchS390):        TargetArchS390,
	string(TargetArchS390x):       TargetArchS390x,
	string(TargetArchSparc64):     TargetArchSparc64,
	string(TargetArchSparc):       TargetArchSparc,
	string(TargetArchWasm):        TargetArchWasm,
}
