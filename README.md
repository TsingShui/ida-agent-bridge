# ida-agent-bridge

[English](README.en.md)

**让 AI 像读源码一样读二进制。**

ida-agent-bridge 是一个无头的 IDA Pro 桥，把 IDA 的全部能力——反编译、交叉引用、类型系统、字节级操作——暴露为纯文本短连接协议。反编译结果实时同步到本地文件系统；重命名、注释、patch 字节——改动瞬间落盘，调用方级联刷新。

一条管道，从二进制到答案。

## 30 秒体验

```
$ ida-bridge a.out &
INFO  sync done in 47.2s

$ cc "分析 a.out 里的 JNI 函数，找出签名逻辑"
```

Agent 自动开始工作：

```
> 读 ida-bridge-a.out/function_index.tsv，搜 jni...
  找到 3 个函数：jni_sign_data (0x401320)、jni_verify_sig (0x4014d8)、JNI_OnLoad (0x4012a0)

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

> 读 ida-bridge-a.out/decompile/401320.c  ← 确认同步
  ; Java_com_example_Crypto_sign @ 0x401320  ✓

结论：签名使用 HMAC-SHA256，密钥硬编码在 g_secret_key (0x60A0B0)，长度 32 字节。
```

**这就是它的全部理念：** Agent 读文件系统发现函数，发一行命令获取伪代码，再发一行命令追踪引用——如同人类逆向工程师在 IDA 里的操作流程，只是每一步都是可以管道化的纯文本。

---

## 安装

**环境要求：** IDA Pro 9.1+、Python 3.13+、[uv](https://docs.astral.sh/uv/)

```bash
# 1. 设置 IDA 路径
# macOS 示例：
export IDADIR="/Applications/IDA Professional 9.3.app/Contents/MacOS"

# 2. 安装
git clone https://github.com/TsingShui/ida-agent-bridge.git ~/.claude/skills/ida-agent-bridge
uv tool install -e ~/.claude/skills/ida-agent-bridge
```

两行完事。

## 使用

```bash
ida-bridge a.out              # 启动，导出到 ./ida-bridge-a.out/
ida-bridge a.out --shell      # 另开交互 shell（端口 13121）
ida-bridge a.out --repl-only  # 仅启动 REPL，跳过导出
```

首次启动做一次全量导出（IDA 自动分析 + 反编译所有函数）。之后每次启动对比 CRC32 hash，只增量导出变更函数，秒级完成。

---

## 设计理念

### 文件系统即 API

启动后，二进制的全部结构被映射为本地文件——Agent 无需任何 SDK，`cat` 一个文件就能读到伪代码：

```
ida-bridge-a.out/
├── decompile/            每个函数一个 .c 文件（伪代码 + 元数据）
├── function_index.tsv    全量函数索引（地址、名称、复杂度指标、调用图）
├── strings.tsv           字符串表
├── imports.tsv           导入表
├── exports.tsv           导出表
├── hash_index.json       CRC32 增量检测
└── export_config.json    导出配置
```

### 实时同步

通过 REPL 重命名函数、修改注释、patch 字节——对应的 `.c` 文件和索引瞬间更新，调用方级联刷新：

| 操作 | 更新范围 |
|------|----------|
| 重命名函数/符号 | 该函数 + 所有 caller |
| 修改注释 | 该函数 |
| 重命名栈帧变量 | 该函数 |
| 修改类型信息 | 该函数 |
| patch 字节（代码段） | 该函数 |
| patch 字节（数据段） | strings.tsv |
| 删除函数 | 删除 .c 文件 + 更新索引 |

### Unix 哲学：一切皆文本

每条命令输出纯文本到 stdout。不需要 JSON 解析器，不需要 SDK——`grep`、`awk`、`sort` 就是你的工具箱：

```bash
# 找被调用最多的前 10 个函数
echo '!afl' | nc localhost 13120 | sort -t= -k2 -rn | head -10

# 所有大于 0x200 字节的未命名函数
echo '!afl' | nc localhost 13120 | awk -F'\t' '$3 >= 0x200 && $2 ~ /^sub_/'

# 从伪代码提取所有被调用函数名
echo '!pdc main' | nc localhost 13120 | grep -oP '\b\w+(?=\()' | sort -u

# 批量搜索引用加密相关字符串的函数
ADDR=$(echo '!iz encrypt' | nc localhost 13120 | awk 'NR==1{print $1}')
echo "!axt $ADDR" | nc localhost 13120
```

---

## 命令速查

所有命令通过 `echo '!cmd' | nc localhost 13120` 短连接发送，地址支持十六进制（`0x1388`）或符号名（`main`）。

**查询**

```
!afl [pat]                  函数列表（支持模糊搜索）
!afi <addr|name>            函数详情
!iz  [pat]                  字符串搜索
!axi <name>                 导入符号的调用点
!axt <addr|name>            交叉引用 to
!axf <addr|name>            交叉引用 from
!deps <addr|name> [d=3]     递归调用链
```

**反编译 / 反汇编**

```
!pdc <addr|name> [-s]       伪代码（-s 去掉变量声明）
!pdf <addr|name>            整函数反汇编（带 CFG 标注）
!pd  <addr|name> [n=16]     从地址反汇编 n 条指令
!mc  <addr|name> [maturity] 微码
```

**修改**

```
!afn <addr|name> <new_name> 重命名函数
!cc  <addr|name> <text>     设函数注释
!ca  <addr> <text>          设地址注释
```

**工具**

```
!hd  <addr|name> [n=64]     hexdump
!sb  <hex> [start] [end]    搜字节序列
!syms <path>                导出符号表
!ping                       探活，返回打开的文件路径
!pwd                        工作目录
```

```bash
echo '!quit' | nc localhost 13120      # 关闭服务
```

---

## Python 脚本

命令不够用时发 Python 脚本。`db`（[ida-domain](https://github.com/kohnakagawa/ida-domain)）已预注入，原生 `ida_*` 模块同样可用：

```bash
cat script.py | nc localhost 13120
```

```python
# 找大函数 + 高调用量 → 可能是核心逻辑
for func in db.functions.get_all():
    size = func.end_ea - func.start_ea
    name = db.functions.get_name(func)
    if size > 0x500 and name.startswith("sub_"):
        callers = list(db.functions.get_callers(func))
        print(f"{hex(func.start_ea)}  {size:#x}  callers={len(callers)}  {name}")
```

脚本中的修改（重命名、注释等）同样自动触发文件系统同步。

## 交互 Shell

给人用的模式——带命令历史和实时补全：

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
```

---

## License

MIT
