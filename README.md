# ida-agent-bridge

[English](README.en.md)

CLI 优先、无头、AI 原生的 IDA Pro 分析桥，遵循 Unix 设计哲学。每条命令输出纯文本，与 `grep`、`sort`、`awk`、`jq` 等工具自然组合；反编译结果实时同步到本地文件系统——Agent 像读文件一样读二进制，脚本像管道一样串联分析流程。

`ida-pro` `ida-python` `ida-cli` `binary-analysis` `reverse-engineering` `ai-agent` `llm-tools` `decompiler`

## 安装

**环境要求：** IDA Pro 9.1.0+

```bash
# macOS 示例：export IDADIR="/Applications/IDA Professional 9.3.app/Contents/MacOS"
[ -z "$IDADIR" ] && echo "请先设置 IDADIR，示例：export IDADIR=\"/Applications/IDA Professional 9.3.app/Contents/MacOS\"" && exit 1

git clone https://github.com/TsingShui/ida-agent-bridge.git ~/.claude/skills/ida-agent-bridge
uv tool install -e ~/.claude/skills/ida-agent-bridge
```

## 快速开始

```bash
ida-bridge a.out              # 启动，导出到 ./ida-bridge-a.out/
ida-bridge a.out --shell      # 同上，另开交互 shell（端口 13121）
ida-bridge a.out --repl-only  # 仅启动 REPL，跳过导出和 hooks
```

**首次启动**：IDA 自动分析 → 反编译预热（耗时随文件体积增长）→ 全量导出

**后续启动**：对比函数 hash，只导出变更函数，秒级完成。

## 核心能力示例

### 实时文件系统

启动后自动导出到本地目录，修改函数名、注释、字节等操作**实时同步**，调用方级联刷新：

```
ida-bridge-<name>/
├── decompile/            每个函数一个 <ADDR>.c，内嵌 func-hash / callers / callees
├── function_index.tsv    函数索引（地址、名称、复杂度指标、调用关系）
├── strings.tsv           字符串表（addr、encoding、contents）
├── imports.tsv           导入表（addr、module、name）
└── exports.tsv           导出表（addr、name）
```

以下操作会自动触发对应文件的重新导出：

| 操作 | 更新范围 |
|------|----------|
| 重命名函数/符号 | 该函数 + 所有 caller |
| 修改注释（地址级、函数级、行内） | 该函数 |
| 重命名栈帧变量 | 该函数 |
| 修改类型信息 | 该函数 |
| patch 字节（代码段） | 该函数 |
| patch 字节（数据段） | strings.tsv |
| 删除函数 | 删除对应 .c 文件，更新索引 |

### 反编译

```bash
$ echo '!pdc _WPACKET_close' | nc localhost 13120   # 或用地址：!pdc 0x1388
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

### 反汇编

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

### 交叉引用

```bash
$ echo '!axt _WPACKET_close' | nc localhost 13120
0x4030    CALL_NEAR  [in: _DTLSv1_listen]
0x403c    CALL_NEAR  [in: _DTLSv1_listen]
0x599f0   CALL_NEAR  [in: _tls_post_encryption_processing_default]
0x5c258   CALL_NEAR  [in: _tls_construct_extensions]
...（共 49 处调用）

$ echo '!axf _WPACKET_close' | nc localhost 13120
0x138c    ORDINARY_FLOW  [func: _WPACKET_close]
```

## Command 支持

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

`addr` 可用十六进制地址（`0x1388`）或符号名（`_WPACKET_close`）。

```bash
echo '__QUIT__' | nc localhost 13120   # 关闭 REPL
```

## Python 脚本

REPL 支持发送任意 Python 脚本，`db`（ida-domain）已预注入，原生 `ida_*` 模块同样可用：

```bash
cat script.py | nc localhost 13120
```

```python
# 批量找可疑大函数（高分支密度 + 未命名）
for func in db.functions.get_all():
    size = func.end_ea - func.start_ea
    name = db.functions.get_name(func)
    if size > 0x500 and name.startswith("sub_"):
        callers = list(db.functions.get_callers(func))
        print(f"{hex(func.start_ea)}  {size:#x}  callers={len(callers)}  {name}")

# 降级到原生 IDA Python
import ida_bytes
data = ida_bytes.get_bytes(0x1388, 16)
print(data.hex())
```

脚本中的重命名、注释等修改自动触发文件系统同步。

## 交互 Shell

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
