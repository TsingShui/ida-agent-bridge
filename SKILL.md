---
name: ida-agent-bridge
description: Use when writing ida-domain scripts, querying .i64 databases, or analyzing binaries. Provides short-connection REPL commands (disasm, xrefs, hexdump, pseudocode, rename) and arbitrary Python script execution piped via nc, with real-time file sync on rename/comment/patch.
---

# IDA Domain API Reference

Use `ida-domain` (Python library on top of IDA Python SDK) to script IDA Pro 9.1.0+.

```bash
uv add "ida-domain>=0.5.0"   # or: pip install "ida-domain>=0.5.0"
```

---

## 工作流

**优先级：REPL 指令 → Python 脚本 → 原生 ida_* 模块**

```
REPL 快捷指令（echo '!cmd' | nc localhost PORT）
      ↓ 指令无法满足（批量操作/复杂逻辑）
Python 脚本（cat script.py | nc localhost PORT）
      ↓ ida-domain 没有封装
原生 ida_* 模块（直接在脚本中调用）
```

---

## 步骤 1：启动 ida-bridge

```bash
PORT=13120

# 启动（已在运行则跳过）
# export_dir 可省略，默认为 ./ida-bridge-<文件名>/
nc -z localhost $PORT 2>/dev/null || ida-bridge /path/to/file.i64 [export_dir] $PORT &
while ! nc -z localhost $PORT 2>/dev/null; do sleep 1; done
```

**首次启动流程**（较慢，一次性）：
1. IDA 自动分析（`auto_wait`）
2. 全量反编译预热，填充类型信息写入 idb（~20s）
3. 全量导出所有函数伪代码到 export_dir

**后续启动**：跳过预热，对比 hash 只导出变更函数，秒级完成。

> **Agent 只使用短连接模式。** `--shell` 是给人用的交互模式，Agent 不应使用。

---

## 步骤 2：优先使用快捷指令

不需要写 Python，直接发单行命令。**这是最快的操作方式。**

### 探索与查询

```bash
echo '!?' | nc localhost $PORT                        # 帮助
echo '!afl' | nc localhost $PORT                      # 列出所有函数
echo '!afl jni' | nc localhost $PORT                  # 搜含 jni 的函数名
echo '!afi main' | nc localhost $PORT                 # 函数详情（大小/调用者/被调用者）
echo '!iz ssl' | nc localhost $PORT                   # 搜含 ssl 的字符串
echo '!axi malloc' | nc localhost $PORT               # 查导入符号 malloc 的所有调用点
```

### 交叉引用

```bash
echo '!axt 0x1234' | nc localhost $PORT               # xrefs to 地址
echo '!axf main' | nc localhost $PORT                 # xrefs from 函数名
```

### 反汇编与伪代码

```bash
echo '!pd 0x1234' | nc localhost $PORT                # 从地址反汇编 16 条（默认）
echo '!pd 0x1234 32' | nc localhost $PORT             # 反汇编 32 条
echo '!pdf main' | nc localhost $PORT                 # 反汇编整个函数（带 CFG block 标注）
echo '!pdc 0x1234' | nc localhost $PORT               # 查看伪代码
echo '!pdc 0x1234 -s' | nc localhost $PORT           # 过滤变量声明（大函数用）
echo '!mc main' | nc localhost $PORT                  # 查看函数微码（默认 generated）
echo '!mc main lvars' | nc localhost $PORT            # 微码：generated/preopt/locopt/calls/glbopt1/glbopt2/glbopt3/lvars
echo '!deps main' | nc localhost $PORT                # 递归调用链（默认深度 3）
echo '!deps main 5' | nc localhost $PORT              # 调用链深度 5
```

### 修改与注释

```bash
echo '!afn 0x1234 sign_request' | nc localhost $PORT  # 重命名函数（自动同步导出，caller 级联刷新）
echo '!cc main entry point' | nc localhost $PORT      # 设置函数级注释（Function Comment）
echo '!ca 0x1234 key check here' | nc localhost $PORT # 设置地址级注释（Address Comment）
echo '!sb  01 14 40 f9' | nc localhost $PORT           # 搜索字节序列（全局）
echo '!sb  01 14 40 f9 0x1000 0x5000' | nc localhost $PORT  # 限定地址范围搜索
echo '!hd  0x1234' | nc localhost $PORT                # hexdump 64 字节（默认）
echo '!hd  0x1234 128' | nc localhost $PORT           # hexdump 128 字节
echo '!hd  func_name' | nc localhost $PORT            # 符号名同样支持
echo '!pwd' | nc localhost $PORT                      # 当前工作目录
```

地址和函数名均可互换（`0x...` 十六进制地址或符号名）。

### 与 Bash 工具联动

REPL 输出是纯文本，可直接接 `grep`、`sort`、`awk`、`jq` 等工具处理，无需额外解析。

```bash
# 找被调用最多的函数
echo '!afl' | nc localhost $PORT | sort -t= -k2 -rn | head -10

# 找所有大于 0x200 字节的未命名函数
echo '!afl' | nc localhost $PORT | awk -F'\t' '$3 >= 0x200 && $2 ~ /^sub_/'

# 从伪代码提取所有被调用函数名
echo '!pdc _wpacket_intern_close' | nc localhost $PORT | grep -oP '\b\w+(?=\()' | sort -u

# 找包含特定字符串的函数（先搜字符串，再查引用）
ADDR=$(echo '!iz encrypt' | nc localhost $PORT | awk 'NR==1{print $1}')
echo "!axt $ADDR" | nc localhost $PORT

# 批量对所有 JNI 函数生成伪代码并保存
echo '!afl jni' | nc localhost $PORT | awk '{print $1}' | while read addr; do
  echo "!pdc $addr" | nc localhost $PORT > "/tmp/pdc_${addr}.c"
done
```

---

## 步骤 3：复杂操作用 Python 脚本

指令不够用时才写脚本。`db` 已预注入，无需 import。

导出目录结构（启动时指定的 `<export_dir>`，默认 `./ida-bridge-<文件名>/`）：
```
<export_dir>/
├── decompile/            <name>.c  — 每个函数的 Hex-Rays 伪代码
├── strings.tsv           addr\tencoding\tcontents
├── imports.tsv           addr\tmodule\tname
├── exports.tsv           addr\tname
└── function_index.tsv    addr\tname\tlogic_lines\tbranch_density\tcall_density\tstring_density\topaque_density\ttotal_insns\tbitop_density\txor_density\tcaller_count\tfile\tcallers\tcallees
```

```bash
cat my_script.py | nc localhost $PORT

# 关闭 REPL
echo '__QUIT__' | nc localhost $PORT
```

典型脚本模式：

```python
# 批量重命名（hooks 自动同步导出）
for func in db.functions.get_all():
    name = db.functions.get_name(func)
    if name.startswith("sub_") and func.end_ea - func.start_ea > 0x200:
        print(hex(func.start_ea), name)

db.names.set_name(0x12AB, 'sign_request')
```

---

## API 文档规则

**写脚本前必须先读对应 API 文档：**

1. **`${CLAUDE_SKILL_DIR}/reference/ida-domain.md`** — 日常必用 API（函数、名称、字节、xrefs、指令、字符串、导入、类型、伪代码基础、微码基础）。覆盖 ~90% 场景。
2. **`${CLAUDE_SKILL_DIR}/reference/ida-domain-advanced.md`** — Pseudocode CTree 深层操作和 Microcode 修改/分析的高级 API。

**不确定 API 用法时，先 Read 文档，不要在 REPL 里试探。**

`ida-domain` 做不到的降级到原生 `ida_*` 模块。`ida-domain` 对象可直接传给原生 SDK 函数。

| Avoid | Do Instead |
|-------|------------|
| `idc.*` functions | Use `ida_*` modules |
| Hardcoded addresses | Use names, patterns, or xrefs |

