# ida-agent-bridge

[中文](README.md)

A CLI-first, headless, AI-native IDA Pro bridge built on Unix philosophy. Every command outputs plain text to stdout — pipe it directly into `grep`, `sort`, `awk`, `jq` or any shell tool. Decompilation results sync to the local filesystem in real time; agents read binaries like files, scripts chain analysis like pipelines.

`ida-pro` `ida-python` `ida-cli` `binary-analysis` `reverse-engineering` `ai-agent` `llm-tools` `decompiler`

## Installation

**Requirements:** IDA Pro 9.1.0+

```bash
# macOS example: export IDADIR="/Applications/IDA Professional 9.3.app/Contents/MacOS"
[ -z "$IDADIR" ] && echo "Set IDADIR first, e.g. export IDADIR=\"/Applications/IDA Professional 9.3.app/Contents/MacOS\"" && exit 1

git clone https://github.com/TsingShui/ida-agent-bridge.git ~/.claude/skills/ida-agent-bridge
uv tool install ~/.claude/skills/ida-agent-bridge
```

## Quick Start

```bash
ida-bridge a.out              # start, export to ./ida-bridge-a.out/
ida-bridge a.out --shell      # same, plus interactive shell on port 13121
ida-bridge a.out --repl-only  # REPL only, skip export and hooks
```

**First run:** IDA auto-analysis → decompilation warmup (grows with binary size) → full export

**Subsequent runs:** compare function hashes, only re-export changed functions — completes in seconds.

## Core Capabilities

### Real-time File System

On startup, all functions are exported to a local directory. Rename, comment, byte patch — changes sync immediately, callers cascade:

```
ida-bridge-<name>/
├── decompile/            one <ADDR>.c per function, embedding func-hash / callers / callees
├── function_index.tsv    function index (addr, name, complexity metrics, call relations)
├── strings.tsv           string table (addr, encoding, contents)
├── imports.tsv           import table (addr, module, name)
└── exports.tsv           export table (addr, name)
```

| Operation | Updates |
|-----------|---------|
| Rename function/symbol | that function + all callers |
| Edit comment (address, function, inline) | that function |
| Rename stack frame variable | that function |
| Edit type info | that function |
| Patch bytes (code segment) | that function |
| Patch bytes (data segment) | strings.tsv |
| Delete function | removes .c file, updates index |

### Decompile

```bash
$ echo '!pdc _WPACKET_close' | nc localhost 13120   # or by address: !pdc 0x1388
; _WPACKET_close @ 0x1388
void __fastcall WPACKET_close(int64x2_t *a1)
{
  _QWORD *v1; // x1

  v1 = (_QWORD *)a1[2].i64[1];
  if ( v1 )
  {
    if ( *v1 )
      wpacket_intern_close(a1, v1, 1);
  }
}
```

### Disassemble

```bash
$ echo '!pdf _WPACKET_close' | nc localhost 13120
; block 0  [0x1388 - 0x1390]
0x1388  LDR             X1, [X0,#0x28]; void *
0x138c  CBZ             X1, loc_13A0    ; true→ 0x13a0  false→ 0x1390
; block 1  [0x1390 - 0x1398]
0x1390  LDR             X8, [X1]
0x1394  CBZ             X8, loc_13A0    ; true→ 0x13a0  false→ 0x1398
; block 2  [0x1398 - 0x13a0]
0x1398  MOV             W2, #1
0x139c  B               _wpacket_intern_close    ; → 0x15b8
; block 3  [0x13a0 - 0x13a8]
0x13a0  MOV             W0, #0
0x13a4  RET
```

### Cross-references

```bash
$ echo '!axt _WPACKET_close' | nc localhost 13120
0x4030    CALL_NEAR  [in: _DTLSv1_listen]
0x403c    CALL_NEAR  [in: _DTLSv1_listen]
0x599f0   CALL_NEAR  [in: _tls_post_encryption_processing_default]
0x5c258   CALL_NEAR  [in: _tls_construct_extensions]
...(49 call sites total)

$ echo '!axf _WPACKET_close' | nc localhost 13120
0x138c    ORDINARY_FLOW  [func: _WPACKET_close]
```

## Commands

```
$ echo '!?' | nc localhost 13120
!iz  [pat]               list strings
!afl [pat]               list functions
!afi <addr|name>         function details
!axt <addr|name>         xrefs to
!axf <addr|name>         xrefs from
!axi <name>              callers of import symbol
!pd  <addr|name> [n=16]  disassemble n instructions
!pdf <addr|name>         disassemble whole function
!pdc <addr|name> [-s]    pseudocode (-s strips var decls)
!deps <addr|name> [d=3]  recursive call chain
!cc  <addr|name> <text>  set function comment
!ca  <addr> <text>       set address comment
!afn <addr|name> <name>  rename function
!mc  <addr|name> [maturity]  microcode
!sb  <hex> [start] [end]     search byte sequence
!hd  <addr|name> [n=64]      hexdump
!pwd                         working directory
```

`addr` accepts hex address (`0x1388`) or symbol name (`_WPACKET_close`).

```bash
echo '__QUIT__' | nc localhost 13120   # shut down REPL
```

## Python Scripts

The REPL accepts arbitrary Python scripts. `db` (ida-domain) is pre-injected; native `ida_*` modules are also available:

```bash
cat script.py | nc localhost 13120
```

```python
# find large unnamed functions
for func in db.functions.get_all():
    size = func.end_ea - func.start_ea
    name = db.functions.get_name(func)
    if size > 0x500 and name.startswith("sub_"):
        callers = list(db.functions.get_callers(func))
        print(f"{hex(func.start_ea)}  {size:#x}  callers={len(callers)}  {name}")

# fall back to native IDA Python
import ida_bytes
data = ida_bytes.get_bytes(0x1388, 16)
print(data.hex())
```

Rename, comment, and other modifications inside scripts automatically trigger file sync.

## Interactive Shell

```bash
ida-bridge a.out --shell
rlwrap nc localhost 13121
```

```
> !afl jni
0x4012a0  JNI_OnLoad       0x80   callers=0
0x401320  jni_sign_data    0x1b4  callers=1
0x4014d8  jni_verify_sig   0xc8   callers=1

> !deps jni_sign_data 2
jni_sign_data  [0x401320]
  CRYPTO_sign  [0x402100]
    EVP_DigestSign  [0x403800]
    ...

> !afn 0x401320 Java_com_example_sign
renamed 0x401320: jni_sign_data → Java_com_example_sign

> exit
```
