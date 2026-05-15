# ida-agent-bridge

[中文](README.md)

**Give your AI agent eyes into compiled binaries.**

ida-agent-bridge is a headless IDA Pro bridge that exposes IDA's full power — decompilation, cross-references, type system, byte-level ops — as a plain-text short-connection protocol. Decompilation results sync to the local filesystem in real time; rename, comment, patch — changes hit disk instantly, callers cascade.

One pipe, from binary to answer.

## 30-Second Demo

```
$ ida-bridge a.out &
INFO  sync done in 47.2s

$ cc "analyze the JNI functions in a.out, find the signing logic"
```

The agent starts working autonomously:

```
> read ida-bridge-a.out/function_index.tsv, search jni...
  found 3 functions: jni_sign_data (0x401320), jni_verify_sig (0x4014d8), JNI_OnLoad (0x4012a0)

> echo '!pdc 0x401320' | nc localhost 13120
  void *jni_sign_data(JNIEnv *env, jobject thiz, jbyteArray data) {
      v3 = HMAC_CTX_new();
      HMAC_Init_ex(v3, &g_secret_key, 32, EVP_sha256(), 0);
      ...
  }

> echo '!axt 0x401320' | nc localhost 13120
  0x4012a0  CALL_NEAR  [in: JNI_OnLoad]

> echo '!afn 0x401320 Java_com_example_Crypto_sign' | nc localhost 13120
  renamed: jni_sign_data → Java_com_example_Crypto_sign

> read ida-bridge-a.out/decompile/401320.c  ← confirm sync
  ; Java_com_example_Crypto_sign @ 0x401320  ✓

Conclusion: signing uses HMAC-SHA256 with a hardcoded key at g_secret_key (0x60A0B0), 32 bytes.
```

**That's the entire idea:** the agent reads the filesystem to discover functions, sends a one-liner for pseudocode, another one-liner to trace references — mirroring a human reverse engineer's workflow in IDA, except every step is pipeable plain text.

---

## Install

**Requirements:** IDA Pro 9.1+, Python 3.13+, [uv](https://docs.astral.sh/uv/)

```bash
# 1. Set IDA path
# macOS example:
export IDADIR="/Applications/IDA Professional 9.3.app/Contents/MacOS"

# 2. Install
git clone https://github.com/TsingShui/ida-agent-bridge.git ~/.claude/skills/ida-agent-bridge
uv tool install -e ~/.claude/skills/ida-agent-bridge
```

Two lines, done.

## Usage

```bash
ida-bridge a.out              # start, export to ./ida-bridge-a.out/
ida-bridge a.out --human-shell      # plus interactive shell on port 13121
ida-bridge a.out --skip-export  # REPL only, skip export
```

First run does a full export (IDA auto-analysis + decompile all functions). Subsequent runs compare CRC32 hashes, only re-export changed functions — completes in seconds.

---

## Design

### Filesystem as API

On startup, the entire binary structure is mapped to local files — the agent needs no SDK, just `cat` a file to read pseudocode:

```
ida-bridge-a.out/
├── decompile/            one .c per function (pseudocode + metadata)
├── function_index.tsv    full function index (addr, name, metrics, call graph)
├── strings.tsv           string table
├── imports.tsv           import table
├── exports.tsv           export table
├── hash_index.json       CRC32 incremental detection
└── export_config.json    export settings
```

### Real-time Sync

Rename a function, edit a comment, patch bytes via REPL — the corresponding `.c` files and index update instantly, callers cascade:

| Operation | Scope |
|-----------|-------|
| Rename function/symbol | that function + all callers |
| Edit comment | that function |
| Rename stack variable | that function |
| Edit type info | that function |
| Patch bytes (code) | that function |
| Patch bytes (data) | strings.tsv |
| Delete function | remove .c + update index |

### Unix Philosophy: Everything is Text

Every command outputs plain text to stdout. No JSON parser, no SDK — `grep`, `awk`, `sort` are your toolkit:

```bash
# top 10 most-called functions
echo '!afl' | nc localhost 13120 | sort -t= -k2 -rn | head -10

# all unnamed functions larger than 0x200 bytes
echo '!afl' | nc localhost 13120 | awk -F'\t' '$3 >= 0x200 && $2 ~ /^sub_/'

# extract all callee names from pseudocode
echo '!pdc main' | nc localhost 13120 | grep -oP '\b\w+(?=\()' | sort -u

# find functions referencing crypto-related strings
ADDR=$(echo '!iz encrypt' | nc localhost 13120 | awk 'NR==1{print $1}')
echo "!axt $ADDR" | nc localhost 13120
```

---

## Command Reference

All commands are sent via `echo '!cmd' | nc localhost 13120`. Addresses accept hex (`0x1388`) or symbol names (`main`).

**Query**

```
!afl [pat]                  list functions (fuzzy search)
!afi <addr|name>            function details
!iz  [pat]                  search strings
!axi <name>                 callers of import symbol
!axt <addr|name>            xrefs to
!axf <addr|name>            xrefs from
!deps <addr|name> [d=3]     recursive call chain
```

**Decompile / Disassemble**

```
!pdc <addr|name> [-s]       pseudocode (-s strips var decls)
!pdf <addr|name>            full function disassembly (with CFG)
!pd  <addr|name> [n=16]     disassemble n instructions from addr
!mc  <addr|name> [maturity] microcode
```

**Modify**

```
!afn <addr|name> <new_name> rename function
!cc  <addr|name> <text>     set function comment
!ca  <addr> <text>          set address comment
```

**Utilities**

```
!hd  <addr|name> [n=64]     hexdump
!sb  <hex> [start] [end]    search byte sequence
!syms <path>                export symbol table
!ping                       health check, returns open file path
!pwd                        working directory
!quit                       shut down server
```

---

## Python Scripts

When commands aren't enough, send Python scripts. `db` ([ida-domain](https://github.com/kohnakagawa/ida-domain)) is pre-injected; native `ida_*` modules also available:

```bash
cat script.py | nc localhost 13120
```

```python
# find large + high-caller functions → likely core logic
for func in db.functions.get_all():
    size = func.end_ea - func.start_ea
    name = db.functions.get_name(func)
    if size > 0x500 and name.startswith("sub_"):
        callers = list(db.functions.get_callers(func))
        print(f"{hex(func.start_ea)}  {size:#x}  callers={len(callers)}  {name}")
```

Modifications inside scripts (rename, comment, etc.) automatically trigger filesystem sync.

## Interactive Shell

For humans — with command history and live feedback:

```bash
ida-bridge a.out --human-shell
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
```

---

## License

MIT
