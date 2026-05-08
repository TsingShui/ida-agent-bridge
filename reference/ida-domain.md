# ida-domain API 参考

> `ida-domain` 是 IDA Pro Python SDK 的上层封装，提供更简洁一致的 API。需要 IDA Pro 9.1.0+。

## 安装与打开

```bash
uv add "ida-domain>=0.5.0"   # pip install "ida-domain>=0.5.0"
```

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

# 基础打开（自动分析）
opts = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open('/path/to/file.i64', opts) as db:
    # 所有操作在这里
    pass

# 已有 .i64 直接打开，关闭自动分析
opts = IdaCommandOptions(auto_analysis=False, new_database=False)
with Database.open('/path/to/file.i64', opts) as db:
    pass

# IDA GUI 里获取当前数据库
db = Database.open()
```

`IdaCommandOptions` 常用字段：`auto_analysis`、`processor`（如 `"arm"`）、`loading_address`、`new_database`。

## 架构总览

所有操作通过 `db` 的 handler 属性访问：

```
db
├── db.functions        # 函数
├── db.names            # 符号名
├── db.segments         # 内存段
├── db.bytes            # 字节读写
├── db.xrefs            # 交叉引用
├── db.instructions     # 指令解码
├── db.comments         # 注释
├── db.strings          # 字符串列表
├── db.heads            # 代码/数据项
├── db.entries          # 入口点
├── db.imports          # 导入表
├── db.types            # 类型系统
├── db.pseudocode       # 反编译
├── db.microcode        # 微码
├── db.flowchart        # 控制流图（通过 db.functions.get_flowchart() 获取）
├── db.signature_files  # FLIRT 签名
└── db.hooks            # 事件钩子
```

`ida-domain` 对象（`func_t`、`insn_t`、`segment_t`）可直接传给原生 `ida_*` 模块。Domain API 做不到的事降级到原生 SDK。

## 数据库信息

```python
db.architecture     # "ARM64"
db.bitness          # 64
db.format           # "ELF64"
db.md5              # "abc123..."
db.sha256           # "..."
db.base_address     # 0x100000000
db.minimum_ea       # 0x100000000
db.maximum_ea       # 0x10001ffff
db.path             # 输入文件路径
db.module           # 模块名
db.filesize         # 文件大小
db.execution_mode   # ExecutionMode.User 或 ExecutionMode.Kernel

# 聚合元数据
meta = db.metadata
print(meta.architecture, meta.bitness)
```

## 函数

```python
# 遍历所有函数
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{name} @ 0x{func.start_ea:x} - 0x{func.end_ea:x}")

len(db.functions)  # 函数总数

# 获取特定函数
func = db.functions.get_at(0x100001000)        # 按地址
func = db.functions.get_by_name('main')        # 按名称
func = db.functions.get_next(0x100001000)      # 下一个函数
```

### 函数属性

```python
func.start_ea       # 起始地址
func.end_ea         # 结束地址
func.flags          # 原始标志位

db.functions.get_flags(func)        # FunctionFlags 枚举
db.functions.is_far(func)           # bool
db.functions.does_return(func)      # 是否返回
```

`FunctionFlags` 常用值：`NORET`（不返回）、`LIB`（库函数）、`THUNK`（跳板）、`LUMINA`（Lumina 提供）

### 函数操作

```python
db.functions.create(0x100001000)         # 创建函数
db.functions.remove(0x100001000)         # 删除函数
db.functions.set_name(func, 'my_func')   # 重命名
```

### 反汇编

```python
# 逐条指令
for insn in db.functions.get_instructions(func):
    disasm = db.instructions.get_disassembly(insn)
    print(f"0x{insn.ea:x}: {disasm}")

# 文本行列表
lines = db.functions.get_disassembly(func, remove_tags=True)
for line in lines:
    print(line)
```

### 调用关系

```python
# 谁调用了这个函数
for caller in db.functions.get_callers(func):
    print(f"被 {db.functions.get_name(caller)} 调用")

# 更详细的信息（含调用指令地址）
for info in db.xrefs.get_callers(func.start_ea):
    print(f"0x{info.ea:x} in {info.name}")

# 这个函数调用了谁
for callee in db.functions.get_callees(func):
    print(f"调用 {db.functions.get_name(callee)}")
```

### 局部变量

```python
lvars = db.functions.get_local_variables(func)
for v in lvars:
    print(f"{v.name}: size={v.size}, arg={v.is_argument}, type={v.type_str}")

# 查找变量（按名称）
lvar = db.functions.get_local_variable_by_name(func, 'result')

# 函数注释
db.functions.set_comment(func, 'important function')
print(db.functions.get_comment(func))
refs = db.functions.get_local_variable_references(func, lvar)
for ref in refs:
    print(f"  {ref.access_type.name} at line {ref.line_number}: {ref.code_line}")
```

### 代码块（主块和尾块）

```python
for chunk in db.functions.get_chunks(func):
    kind = "主块" if chunk.is_main else f"尾块(owner: {db.functions.get_tail_info(chunk).owner_name})"
    print(f"0x{chunk.start_ea:x} - 0x{chunk.end_ea:x} {kind}")
```

### 伪代码与微码

```python
lines = db.pseudocode.get_text(func)   # 推荐，直接返回 List[str]，接受 int 或 func_t
pseudo = db.functions.get_pseudocode(func)
print(str(pseudo))           # 完整伪代码字符串
print(pseudo.to_text())      # 行列表 List[str]

lines = db.microcode.get_text(func)    # 微码文本行，需传 func_t 对象
```

## 符号名

```python
# 获取/设置名称
name = db.names.get_at(0x100001000)                   # 可能为 None
db.names.set_name(0x100001000, 'decrypt_payload')     # 设置
db.names.set_name(0x100001000, '')                    # 删除
db.names.force_name(0x100001000, 'decrypt')           # 冲突时自动加后缀

# 遍历所有命名
for addr, name in db.names.get_all():
    print(f"0x{addr:x}: {name}")

len(db.names)  # 命名总数

# 属性操作
db.names.is_public_name(0x100001000)    # 是否公开名
db.names.make_name_public(0x100001000)
db.names.is_weak_name(0x100001000)      # 是否弱名
db.names.make_name_weak(0x100001000)

# Demangle
db.names.get_demangled_name(0x100001000)           # 获取 demangled 名
db.names.demangle_name('_ZN3Foo3barEv')            # 手动 demangle
```

`SetNameFlags` 常用：`SN_NOCHECK`（默认，自动修正非法字符）、`SN_CHECK`（遇非法字符失败）、`SN_PUBLIC`（公开名）、`SN_FORCE`（冲突时尝试变体）

## 内存段

```python
# 遍历
for seg in db.segments:
    name = db.segments.get_name(seg)
    size = db.segments.get_size(seg)
    print(f"0x{seg.start_ea:x} {name} size={size}")

db.segments.get_by_name('.text')  # 按名查找
seg = db.segments.get_at(0x100001000)  # 按地址获取所在段

# 权限
from ida_domain.segments import SegmentPermissions
db.segments.set_permissions(seg, SegmentPermissions.READ | SegmentPermissions.EXEC)
db.segments.add_permissions(seg, SegmentPermissions.WRITE)

# 创建
from ida_domain.segments import PredefinedClass, AddSegmentFlags
db.segments.add(
    seg_para=0, start_ea=0x20000000, end_ea=0x20001000,
    seg_name='.newseg', seg_class=PredefinedClass.DATA
)
# 追加到末尾
db.segments.append(seg_para=0, seg_size=0x1000, seg_name='.extra')
```

`PredefinedClass`：`CODE`、`DATA`、`CONST`、`STACK`、`BSS`、`XTRN`、`COMM`、`ABS`

## 字节操作

### 读取

```python
b = db.bytes.get_byte_at(0x100001000)       # 1 字节
w = db.bytes.get_word_at(0x100001000)       # 2 字节
d = db.bytes.get_dword_at(0x100001000)      # 4 字节
q = db.bytes.get_qword_at(0x100001000)      # 8 字节
raw = db.bytes.get_bytes_at(0x100001000, 16)  # N 字节 → bytes
```

### 写入与 Patch

```python
db.bytes.set_byte_at(0x100001000, 0x90)         # 直接写入
db.bytes.patch_byte_at(0x100001000, 0x90)       # Patch（保留原始值）
db.bytes.patch_bytes_at(0x100001000, b'\x90'*4) # 批量 Patch

db.bytes.revert_byte_at(0x100001000)            # 恢复原始值
orig = db.bytes.get_original_byte_at(0x100001000)
```

### 搜索

```python
# 字节模式
ea = db.bytes.find_bytes_between(b'\x55\x48\x89\xe5')
results = db.bytes.find_binary_sequence(b'\x55\x48')  # 全部匹配

# 文本
ea = db.bytes.find_text_between('SSL_read')

# 立即数
ea = db.bytes.find_immediate_between(0xDEADBEEF)
```

### 字符串读取

```python
s = db.bytes.get_string_at(0x100001000)          # IDA 类型感知
s = db.bytes.get_cstring_at(0x100001000)         # C 风格 null 结尾，手动读字节
```

### 创建数据项

```python
db.bytes.create_byte_at(0x100001000, count=4)      # 4 个 byte
db.bytes.create_dword_at(0x100001000, count=2)     # 2 个 dword
db.bytes.create_string_at(0x100001000)             # 字符串
db.bytes.create_struct_at(0x100001000, count=1, tid=42)  # 结构体
```

### 类型检查

```python
db.bytes.is_code_at(ea)       # 代码?
db.bytes.is_data_at(ea)       # 数据?
db.bytes.is_unknown_at(ea)    # 未定义?
db.bytes.is_head_at(ea)       # 数据项起始?
db.bytes.is_string_literal_at(ea)  # 字符串字面量?
```

### 浮点读取

```python
f = db.bytes.get_float_at(0x100001000)    # 4 字节 IEEE 754 float → float 或 None
d = db.bytes.get_double_at(0x100001000)   # 8 字节 IEEE 754 double → float 或 None
```

### 浮点/扩展创建

```python
db.bytes.create_float_at(0x100001000)           # 标记为 float
db.bytes.create_double_at(0x100001000)          # 标记为 double
```

### 扩展 Patch

```python
db.bytes.patch_dword_at(0x100001000, 0xDEADBEEF)   # Patch 4 字节（保留原始值）
db.bytes.patch_qword_at(0x100001000, 0x1122334455667788)  # Patch 8 字节
```

### Head 导航

```python
next_ea = db.bytes.get_next_head(0x100001000)           # 下一个数据项起始地址
prev_ea = db.bytes.get_previous_head(0x100001000)       # 上一个数据项起始地址

# 可选限制范围
next_ea = db.bytes.get_next_head(ea, max_ea=0x100002000)
prev_ea = db.bytes.get_previous_head(ea, min_ea=0x100000000)
```

### 用户名检查

```python
db.bytes.has_user_name_at(ea)   # 该地址是否有用户自定义名称 → bool
```

## 交叉引用

```python
# 所有引用到 ea
for xref in db.xrefs.to_ea(ea):
    print(f"0x{xref.from_ea:x} -> 0x{xref.to_ea:x} {xref.type.name}")

# 所有从 ea 出发的引用
for xref in db.xrefs.from_ea(ea):
    print(f"0x{xref.from_ea:x} -> 0x{xref.to_ea:x}")

# 代码引用
for src in db.xrefs.code_refs_to_ea(func_ea):       # 谁引用了这个函数
    pass
for tgt in db.xrefs.code_refs_from_ea(ea):          # 这个地址引用了谁
    pass

# 调用/跳转
for src in db.xrefs.calls_to_ea(func_ea):      # 谁调用了
for tgt in db.xrefs.calls_from_ea(ea):         # 调用了谁
for src in db.xrefs.jumps_to_ea(ea):           # 谁跳转到
for tgt in db.xrefs.jumps_from_ea(ea):         # 跳转到谁

# 数据引用
for src in db.xrefs.data_refs_to_ea(data_ea):   # 谁引用了这个数据
for reader in db.xrefs.reads_of_ea(data_ea):    # 谁读取了
for writer in db.xrefs.writes_to_ea(data_ea):   # 谁写入了

# 调用者详细信息（含函数名）
for caller in db.xrefs.get_callers(func.start_ea):
    print(f"0x{caller.ea:x}: {caller.name}")
```

`XrefType` 常用：`CALL_NEAR`、`CALL_FAR`、`JUMP_NEAR`、`JUMP_FAR`、`READ`、`WRITE`、`OFFSET`、`ORDINARY_FLOW`

`XrefInfo` 属性：`is_call`、`is_jump`、`is_read`、`is_write`、`is_flow`

## 指令

```python
insn = db.instructions.get_at(0x100001000)     # 解码单条指令
prev = db.instructions.get_previous(0x100001000)  # 上一条指令

# 反汇编文本
text = db.instructions.get_disassembly(insn)
mnem = db.instructions.get_mnemonic(insn)       # 助记符

# 操作数
for op in db.instructions.get_operands(insn):
    # op 类型：RegisterOperand / ImmediateOperand / MemoryOperand / ProcessorSpecificOperand
    print(f"  type={op.type.name}, value={op.get_value()}")

# 指令类型判断
db.instructions.is_call_instruction(insn)
db.instructions.is_indirect_jump_or_call(insn)
db.instructions.breaks_sequential_flow(insn)
```

### 操作数类型

```python
op = db.instructions.get_operand(insn, 0)

# RegisterOperand
if hasattr(op, 'get_register_name'):
    print(op.get_register_name())

# ImmediateOperand
if hasattr(op, 'is_address') and op.is_address():
    print(hex(op.get_value()))

# MemoryOperand
if hasattr(op, 'get_address'):
    addr = op.get_address()
    name = db.names.get_at(addr)  # 获取符号名
```

### 操作数值提取

```python
from ida_domain.operands import RegisterOperand, ImmediateOperand, MemoryOperand

for op in db.instructions.get_operands(insn):
    if isinstance(op, RegisterOperand):
        print(op.get_register_name())   # str，如 "x0"、"rax"
        print(op.register_number)       # int，寄存器编号（property）

    elif isinstance(op, ImmediateOperand):
        print(op.get_value())           # int，立即数值
        print(op.is_address())          # bool，是否为 near/far 地址
        if op.is_address():
            print(op.get_name())        # 符号名或 None

    elif isinstance(op, MemoryOperand):
        print(op.get_address())         # Optional[ea_t]，直接内存地址
        print(op.get_displacement())    # Optional[int]，基址偏移（op_t.addr）
        print(op.is_direct_memory())    # bool，是否直接内存访问
        print(op.is_register_based())   # bool，是否寄存器寻址（含偏移）
        print(op.get_formatted_string()) # Optional[str]，IDA 格式化字符串
```

`OperandType` 枚举：`REGISTER`、`IMMEDIATE`、`NEAR_ADDRESS`、`FAR_ADDRESS`、`MEMORY`、`PHRASE`、`DISPLACEMENT`、`PROCESSOR_SPECIFIC_0..5`

`OperandDataType` 枚举：`BYTE`、`WORD`、`DWORD`、`QWORD`、`FLOAT`、`DOUBLE`、`LDBL`、`CODE` 等

通用属性（所有操作数类型）：`op.type`、`op.data_type`、`op.size_bytes`、`op.size_bits`、`op.number`、`op.is_read()`、`op.is_write()`

## 字符串列表

```python
# 遍历所有已检测字符串
for s in db.strings:
    print(f"0x{s.address:x}: {str(s)}")   # str(s) → UTF-8 解码

s = db.strings.get_at(0x100001000)         # 按地址查找

# 按范围
for s in db.strings.get_between(0x100001000, 0x100002000):
    pass

# 重建字符串列表（自定义参数）
from ida_domain.strings import StringListConfig, StringType
cfg = StringListConfig(
    string_types=[StringType.C, StringType.C_16],
    min_len=4,
    only_ascii_7bit=False,
)
db.strings.rebuild(cfg)
```

`StringType`：`C`（ANSI）、`C_16`（UTF-16）、`PASCAL`、`LEN2`、`LEN4` 等

## 导入表

```python
# 遍历模块
for mod in db.imports:
    print(mod.name)
    for imp in db.imports.get_imports_for_module(mod.index):
        print(f"  {imp.name} @ 0x{imp.address:x}")

# 扁平遍历
for imp in db.imports.get_all_imports():
    print(f"{imp.module_name}!{imp.name}")

# 查找
mod = db.imports.get_module_by_name('libc.so')
imp = db.imports.get_import_by_name('libc.so!printf')
imp = db.imports.get_import_at(0x100001000)

len(db.imports)  # 模块数
db.imports.get_import_count()        # 导入符号总数
list(db.imports.get_module_names())  # ['libc.so', 'kernel32.dll', ...]
list(db.imports.get_import_names())  # ['libc.so!printf', ...]
list(db.imports.get_import_addresses())  # [0x1000, 0x1008, ...]
db.imports.exists('libc.so!malloc')  # 检查是否存在

# 模块聚合
mods = list(db.imports.get_all_modules())      # List[ImportModuleInfo]
count = db.imports.get_module_count()          # int，模块总数
mod = db.imports.get_module_at_index(0)        # ImportModuleInfo（按序号）

# 按名称检查单个导入是否有符号名
imp = db.imports.get_import_by_name('libc.so!printf')
if imp and imp.has_name():
    print(imp.name)   # 有符号名（而非仅序号）
```

## 入口点

```python
for entry in db.entries:
    print(f"ord={entry.ordinal} 0x{entry.address:x} {entry.name}")
    if entry.has_forwarder():
        print(f"  -> {entry.forwarder_name}")

entry = db.entries.get_by_name('main')
entry = db.entries.get_at(0x100001000)

# 添加入口点
db.entries.add(0x100001000, 'my_entry', make_code=True)
db.entries.rename(1, 'new_name')

# 聚合查询
all_entries = list(db.entries.get_all())         # List[EntryInfo]
count = db.entries.get_count()                   # int，入口点总数
ordinals = list(db.entries.get_ordinals())       # List[int]，所有序号
names = list(db.entries.get_names())             # List[str]，所有名称
addrs = list(db.entries.get_addresses())         # List[ea_t]，所有地址

# 转发器
from ida_domain.entries import ForwarderInfo
for fwd in db.entries.get_forwarders():          # Iterator[ForwarderInfo]
    print(f"ord={fwd.ordinal} -> {fwd.name}")

db.entries.exists(1)                             # 检查序号为 1 的入口点是否存在
```

## 注释

```python
from ida_domain.comments import CommentKind, ExtraCommentKind

# 普通/可重复注释
db.comments.set_at(0x100001000, 'decrypt key here')
info = db.comments.get_at(0x100001000)
db.comments.delete_at(0x100001000)

# Extra 注释（行前/行后）
db.comments.set_extra_at(0x100001000, 0, 'before this line', ExtraCommentKind.ANTERIOR)
db.comments.set_extra_at(0x100001000, 0, 'after this line', ExtraCommentKind.POSTERIOR)

# 遍历所有注释
for info in db.comments.get_all():
    print(f"0x{info.ea:x}: {info.comment}")
```

## Heads（代码/数据项）

```python
# 遍历所有项
for ea in db.heads:
    kind = "code" if db.heads.is_code(ea) else "data" if db.heads.is_data(ea) else "unknown"
    print(f"0x{ea:x} {kind}")

# 按范围
for ea in db.heads.get_between(0x100001000, 0x100002000):
    pass

db.heads.is_head(ea)     # 是否为项起始
db.heads.size(ea)        # 项大小
start, end = db.heads.bounds(ea)  # 项边界
```

## 类型系统

```python
# 获取/设置地址处的类型
tif = db.types.get_at(0x100001000)
db.types.apply_declaration_at(func_ea, 'int __cdecl main(int argc, char **argv)')

# 两步法: 先解析再应用
parsed = db.types.parse_one_declaration(None, 'struct Point { int x; int y; };')
db.types.apply_at(parsed, func_ea)

# 解析声明
tif = db.types.parse_one_declaration(None, 'int __fastcall foo(int x, int y)')
db.types.parse_header_file(til, '/path/to/types.h')      # 解析头文件
db.types.parse_declarations(til, 'typedef int my_int;')  # 解析多个声明

# 遍历已定义类型
for td in db.types.get_all():
    print(db.types.get_details(td).name)
named = list(db.types.get_all(type_kind=TypeKind.NUMBERED))  # 编号类型

t = db.types.get_by_name('Point')

# 类型详情
details = db.types.get_details(tif)
print(details.name, details.size)

# 成员遍历
for m in db.types.get_udt_members(tif):
    print(f"{m.name} offset={m.offset} type={m.type}")
m = db.types.get_udt_member_by_name(tif, 'x')
m = db.types.get_udt_member_by_offset(tif, 0)

# 枚举成员
for m in db.types.get_enum_members(tif):
    print(f"{m.name} = {m.value}")
m = db.types.get_enum_member_by_value(tif, 42)

# 函数参数
for arg in db.types.get_func_arguments(tif):
    print(f"{arg.name}: {arg.type}")
arg = db.types.get_func_argument_by_index(tif, 0)
ret = db.types.get_return_type(tif)

# 指针/数组解包
elem = db.types.get_pointed_type(tif)          # 指向的类型
elem = db.types.get_array_element_type(tif)    # 数组元素类型
n = db.types.get_array_length(tif)             # 数组长度

# 类型创建
void = db.types.create_void()
i32 = db.types.create_primitive(4, signed=True)
f64 = db.types.create_float(8)
ptr = db.types.create_pointer(i32)
arr = db.types.create_array(i32, 100)
```

### Type Builders

```python
# 结构体
builder = db.types.create_struct('MyStruct')
builder.add_member('field1', db.types.create_primitive(4)) \
       .add_member('field2', db.types.create_primitive(8), offset=8) \
       .set_packed(True)
tif = builder.build()                      # 内存中的 tinfo_t
# 或 builder.build_and_save()              # 构建并保存到类型库

# 联合体
builder = db.types.create_union('MyUnion')
builder.add_member('as_int', i32).add_member('as_ptr', ptr)
tif = builder.build()

# 枚举
builder = db.types.create_enum('Status', base_size=4)
builder.add_member('OK', 0).add_member('ERR', 1).set_bitmask(False)
tif = builder.build()

# 函数类型
builder = db.types.create_func_type()
builder.set_return_type(i32) \
       .add_argument('a', i32) \
       .add_argument('b', i32) \
       .set_calling_convention(CallingConvention.FASTCALL)
tif = builder.build()
```

### TypeDetails 层次

```python
details = db.types.get_details(tif)

# 各分类详情（按实际类型返回对应子类或 None）
if details.udt:
    print(f"UDT members: {details.udt.num_members}")
if details.enum:
    print(f"Enum attrs: {details.enum.attributes}")
if details.ptr:
    print(f"Ptr attrs: {details.ptr.attributes}")
if details.array:
    print(f"Array elem: {details.array.element_type}, len={details.array.length}")
if details.func:
    print(f"Func attrs: {details.func.attributes}")
if details.bitfield:
    print(f"Bitfield attrs: {details.bitfield.attributes}")
```

### 类型库

```python
til = db.types.load_library('/path/to/types.til')
db.types.import_from_library(til)               # 全部导入
db.types.import_type(til, 'MyStruct')           # 导入指定类型
db.types.export_type(til, 'MyStruct')           # 导出到库
db.types.copy_type(source_til, dest_til, 'T')   # 库间复制
db.types.save_library(til, '/path/to/types.til')
db.types.unload_library(til)
```

### 序列化

```python
# 按类型解析内存数据
result = db.types.parse_object_at(ea, tif)      # dict 形式
result = db.types.parse_object_from_bytes(data, tif)

# 将类型数据写入内存
db.types.store_object_at(ea, {'x': 1, 'y': 2}, tif)
raw = db.types.serialize_object_to_bytes({'x': 1, 'y': 2}, tif)
```

`TypeApplyFlags`：`GUESSED`（默认）、`DEFINITE`
`CallingConvention`：`CDECL`、`STDCALL`、`FASTCALL`、`THISCALL`、`DEFAULT`

### 类型构建

Type Builder 完整签名及持久化选项：

```python
# StructBuilder — 链式调用，支持对齐控制
builder = db.types.create_struct('Header')
builder.add_member('magic', db.types.create_primitive(4))           # 自动计算偏移
builder.add_member('size',  db.types.create_primitive(4), offset=4) # 显式指定偏移
builder.set_packed(True)           # 紧凑模式，不插入 padding
builder.set_alignment(8)           # 设置对齐字节数
tif = builder.build()              # 仅返回 tinfo_t，不写入数据库
tif = builder.build_and_save()                    # 构建并存入本地 til
tif = builder.build_and_save(library=custom_til)  # 构建并存入指定库

# EnumBuilder — 同样支持 build_and_save
builder = db.types.create_enum('Color', base_size=4)
builder.add_member('RED', 0).add_member('GREEN', 1).add_member('BLUE', 2)
builder.set_bitmask(False)
tif = builder.build_and_save()

# UnionBuilder — 也支持 build_and_save
builder = db.types.create_union('Variant')
builder.add_member('as_int', db.types.create_primitive(4))
builder.add_member('as_float', db.types.create_float(4))
tif = builder.build_and_save()
```

### 成员统一查询

`get_member` / `get_members` 是 LLM 友好的统一接口，适用于 struct/union、enum 和函数类型：

```python
# get_member(tif, key, by='name'|'offset'|'index'|'value')
m = db.types.get_member(struct_tif, 'x')            # by name（默认）
m = db.types.get_member(struct_tif, 4, by='offset') # by byte offset
m = db.types.get_member(func_tif, 0,  by='index')   # 函数第 0 个参数（仅对函数类型有效，struct 用 by='name' 或 by='offset'）
m = db.types.get_member(enum_tif, 42, by='value')   # 按枚举值查找
# 返回 Optional[UdtMemberInfo | EnumMemberInfo | FuncArgumentInfo]

# get_members：统一迭代所有成员
for m in db.types.get_members(tif):
    print(m.name)

# get_udt_member_by_offset：按偏移查找结构体成员
m = db.types.get_udt_member_by_offset(struct_tif, 8)  # offset=8 处的成员
# -> Optional[UdtMemberInfo]（.name, .type, .offset, .size, .is_bitfield）
```

### 函数类型参数查询

```python
# 获取函数参数个数
count = db.types.get_func_argument_count(func_tif)  # int（非函数类型返回 0）

# 按索引获取单个参数
arg = db.types.get_func_argument_by_index(func_tif, 0)  # FuncArgumentInfo | None
# FuncArgumentInfo 字段：arg.index / arg.name / arg.type

# 迭代所有参数
for arg in db.types.get_func_arguments(func_tif):
    print(f"[{arg.index}] {arg.name}: {arg.type}")
```

### 枚举成员查询

```python
# 按名查找枚举成员
m = db.types.get_enum_member_by_name(enum_tif, 'ERR')  # EnumMemberInfo | None
# EnumMemberInfo 字段：m.name / m.value

# 按值查找
m = db.types.get_enum_member_by_value(enum_tif, 0)

# 获取成员数
count = db.types.get_enum_member_count(enum_tif)       # int

# 迭代所有成员
for m in db.types.get_enum_members(enum_tif):
    print(f"{m.name} = {m.value:#x}")
```

## 签名文件 (FLIRT)

```python
# 应用签名文件
results = db.signature_files.apply('/path/to/signatures.sig')
for r in results:
    print(f"{r.path}: {r.matches} matches")

# 仅探测（不应用）
results = db.signature_files.apply('/path/to/signatures.sig', probe_only=True)

# 获取可用签名文件
files = db.signature_files.get_files()
```

## 控制流图

```python
fc = db.functions.get_flowchart(func)
for block in fc:
    print(f"Block 0x{block.start_ea:x} - 0x{block.end_ea:x}")
    print(f"  succ={block.count_successors()}, pred={block.count_predecessors()}")

    for insn in block.get_instructions():
        print(f"    0x{insn.ea:x}: {db.instructions.get_disassembly(insn)}")

for pred in block.get_predecessors():     # 前驱块
    pass
for succ in block.get_successors():        # 后继块
    pass

len(fc)  # 基本块数量
```

## 微码 (Microcode)

微码是 Hex-Rays 反编译器的中间表示 (IR)，位于汇编指令和伪代码之间。通过 9 个成熟度级别 (`MicroMaturity`) 逐步优化。

### 生成微码

```python
from ida_domain.microcode import MicroMaturity, DecompilationFlags

# 为函数生成微码
mba = db.microcode.generate(func)                                    # 默认 MMAT_GENERATED
mba = db.microcode.generate(func, maturity=MicroMaturity.LVARS)      # 最终成熟度（含局部变量）
mba = db.microcode.generate(func, maturity=MicroMaturity.CALLS)      # 调用分析完成
mba = db.microcode.generate(func, flags=DecompilationFlags.NO_CACHE) # 不使用缓存

# 为地址范围生成
mba = db.microcode.generate_for_range(0x1000, 0x2000)

# 从完整反编译获取（含局部变量信息）
mba = db.microcode.from_decompilation(func)

# 直接获取文本行
lines = db.microcode.get_text(func)
```

`MicroMaturity` 级别：`ZERO` → `GENERATED` → `PREOPTIMIZED` → `LOCOPT` → `CALLS` → `GLBOPT1` → `GLBOPT2` → `GLBOPT3` → `LVARS`

### 遍历层级

```python
mba = db.microcode.generate(func)

# Block → Instruction 两层遍历
for block in mba:
    print(f"Block {block.index}: type={block.block_type.name}, 0x{block.start_ea:x}-0x{block.end_ea:x}")

    for insn in block:
        print(f"  {insn.opcode.name:6s} l={insn.l} r={insn.r} d={insn.d}")

# 跳过哨兵块
for block in mba.blocks(skip_sentinels=True):
    for insn in block:
        pass

# 扁平遍历所有指令
for insn in mba.instructions():
    pass
```

### 查找指令

```python
# 按 opcode 查找
for insn in mba.find_instructions(opcode=MicroOpcode.CALL):
    print(f"call at block {insn.block.index}")

# 查找所有包含全局地址引用的指令
for insn in mba.find_instructions(operand_type=MicroOperandType.GLOBAL_ADDR):
    print(f"global ref at 0x{insn.ea:x}")
```

### MicroBlock 属性

```python
block.index            # 序号
block.block_type       # MicroBlockType: ONE_WAY, TWO_WAY, N_WAY, STOP, EXTERNAL
block.start_ea / end_ea  # 地址范围
block.head / block.tail  # 首/尾指令
block.first_regular_insn  # 首条非断言指令
block.instruction_count   # 指令数
block.predecessor_count / block.successor_count  # 前驱/后继数

# 控制流
block.is_branch         # 是否以条件分支结尾
block.is_simple_goto    # 是否只含一条 goto
block.is_call_block     # 是否包含调用
block.jump_target       # 跳转目标块序号 (条件跳转→d, goto→l, ONE_WAY→serial+1)
block.fall_through      # 条件分支的 fall-through 目标 (仅 TWO_WAY)
```

### MicroInstruction 核心

```python
insn.opcode             # MicroOpcode 枚举
insn.ea                 # 对应原始地址
insn.l / insn.r / insn.d  # 左/右/目标操作数 (均为 MicroOperand)
insn.prev / insn.next   # 链表导航
insn.block              # 所属 MicroBlock

# 类型判断
insn.is_call()               # CALL / ICALL
insn.is_conditional_jump()   # JNZ, JZ, JAE, JB...
insn.is_jump()               # 任意跳转（含 GOTO, JTBL, IJMP）
insn.is_flow()               # 任意控制流（跳转+调用+RET）
insn.is_set()                # SETNZ, SETZ, SETAE...
insn.is_floating_point()     # FADD, FSUB, FMUL...
insn.is_mov()                # MOV
insn.is_combined()           # 组合指令
insn.modifies_dest()         # 是否修改目标操作数
insn.has_side_effects()      # 是否有副作用

# 子指令查找
insn.contains_call()                      # 是否包含调用子指令
insn.find_call(with_helpers=False)        # 查找调用子指令
insn.find_opcode(MicroOpcode.XOR)         # 按 opcode 查找子指令
insn.find_numeric_operand(0xDEAD)         # 查找特定立即数

# 访问者模式
insn.for_all_instructions(visitor)        # 遍历所有子指令
insn.for_all_operands(visitor)            # 遍历所有操作数
```

### MicroOpcode 分类

| 类别 | 操作码 |
|------|--------|
| 数据移动 | `NOP`, `STX`, `LDX`, `LDC`, `MOV`, `NEG`, `LNOT`, `BNOT`, `XDS`, `XDU`, `LOW`, `HIGH` |
| 算术 | `ADD`, `SUB`, `MUL`, `UDIV`, `SDIV`, `UMOD`, `SMOD` |
| 位运算 | `OR`, `AND`, `XOR`, `SHL`, `SHR`, `SAR` |
| 条件设置 | `SETNZ`, `SETZ`, `SETAE`, `SETB`, `SETA`, `SETBE`, `SETG`, `SETGE`, `SETL`, `SETLE`, `SETP`, `SETS`, `SETO` |
| 控制流 | `GOTO`, `JNZ`, `JZ`, `JAE`, `JB`, `JA`, `JBE`, `JG`, `JGE`, `JL`, `JLE`, `JTBL`, `IJMP`, `JCND` |
| 调用/返回 | `CALL`, `ICALL`, `RET` |
| 浮点 | `F2I`, `F2U`, `I2F`, `U2F`, `F2F`, `FNEG`, `FADD`, `FSUB`, `FMUL`, `FDIV` |
| 标志位 | `CFADD`, `OFADD`, `CFSHL`, `CFSHR` |
| 其他 | `PUSH`, `POP`, `UND`, `EXT` |

`MicroOpcode` 属性分类：`is_arithmetic`, `is_bitwise`, `is_shift`, `is_unary`, `is_floating_point`, `is_commutative`, `is_addsub`, `is_xdsu`

### MicroOperand

```python
op = insn.l  # 或 insn.r / insn.d

op.type              # MicroOperandType: REGISTER, NUMBER, GLOBAL_ADDR, STACK_VAR, SUB_INSN, CALL_INFO...
op.size              # 操作数大小（字节）

# 值提取
op.register()        # 寄存器编号（REGISTER 类型）
op.register_name()   # 寄存器名称字符串
op.value()           # 立即数值（NUMBER 类型）
op.signed_value()    # 有符号立即数
op.unsigned_value()  # 无符号立即数
op.global_address()  # 全局地址（GLOBAL_ADDR 类型）
op.stack_offset()    # 栈偏移（STACK_VAR 类型）
op.helper_name()     # helper 名称（HELPER 类型）
op.sub_instruction() # 子指令（SUB_INSN 类型）
op.call_info()       # 调用信息（CALL_INFO 类型）
op.string_value()    # 字符串值（STRING 类型）
op.block_ref()       # 块引用序号（BLOCK_REF 类型）

# 判断（属性，不是方法）
op.is_register / op.is_number / op.is_string
op.is_global_address        # IDA 9.2+
op.is_zero / op.is_one
op.is_positive_constant / op.is_negative_constant
op.is_helper(name: str)     # 方法，需传名称字符串
op.is_constant()            # 方法，是否为编译时常量，返回常量值或 None
op.is_equal_to(42)        # 是否等于指定值
op.has_side_effects()     # 是否有副作用

# 修改
op.set_number(42, size=4)
op.set_register(mreg=0, size=8)
op.set_helper('HIWORD')
op.set_global_addr(0x1000, size=4)
op.change_size(8)         # 改变大小
op.apply_zero_extension(8) / op.apply_sign_extension(8)
```

`MicroOperandType`：`EMPTY`, `REGISTER`, `NUMBER`, `STRING`, `SUB_INSN`, `STACK_VAR`, `GLOBAL_ADDR`, `BLOCK_REF`, `CALL_INFO`, `LOCAL_VAR`, `ADDR_OF`, `HELPER`, `CASE`, `FP_CONST`, `PAIR`, `SCATTERED`

### MicroBlockArray 高级

```python
mba.maturity           # MicroMaturity 枚举
mba.mba_flags          # MbaFlags 位标志
mba.block_count        # 块数量
mba.entry_ea           # 函数入口地址
mba.entry_block        # 入口块 (index 0)

# 局部变量（需要 LVARS 成熟度）
mba.vars               # MicroLocalVars: 可迭代、按名查找
mba.argument_indices   # 参数在 lvar 列表中的索引
mba.return_variable_index  # 返回值变量索引

# 调用分析
mba.analyze_calls(flags=AnalyzeCallsFlags.GUESS)

# 图操作
graph = mba.get_graph()

# 访问者模式
mba.for_all_top_instructions(visitor)  # 遍历所有顶层指令
mba.for_all_instructions(visitor)      # 遍历所有指令（含子指令）
```

### 局部变量 (MicroLocalVars)

```python
# 需要 LVARS 成熟度
mba = db.microcode.generate(func, maturity=MicroMaturity.LVARS)
# 或 mba = db.microcode.from_decompilation(func)

for lvar in mba.vars:
    print(f"{lvar.name}: size={lvar.width}, arg={lvar.is_arg}, type={lvar.type_info}")

lvar = mba.vars.find_by_name('result')
lvar = mba.vars.find_stkvar(spoff=8, width=4)

# 属性
lvar.name / lvar.comment / lvar.width
lvar.type_info         # tinfo_t
lvar.location          # vdloc_t
lvar.definition_address  # 定义地址
lvar.is_arg / lvar.is_result / lvar.is_used
lvar.is_stack_variable() / lvar.is_register_variable()  # 方法
lvar.has_user_name / lvar.has_user_type                  # 属性

# 操作
lvar.set_type(tif)
lvar.set_user_name('new_name')
lvar.set_user_comment('description')
```

### 常见微码分析模式

```python
from ida_domain.microcode import MicroOpcode, MicroOperandType, MicroMaturity

mba = db.microcode.generate(func, maturity=MicroMaturity.CALLS)

# 找到所有直接调用
for insn in mba.find_instructions(opcode=MicroOpcode.CALL):
    target = insn.l.global_address()
    if target:
        callee = db.functions.get_at(target)
        name = db.functions.get_name(callee) if callee else f"0x{target:x}"
        print(f"call {name} at block {insn.block.index}")

# 找到所有间接调用
for insn in mba.find_instructions(opcode=MicroOpcode.ICALL):
    print(f"间接调用 at 0x{insn.ea:x}: target={insn.d}")

# 找到所有对全局变量的引用
for insn in mba.find_instructions(operand_type=MicroOperandType.GLOBAL_ADDR):
    for op in [insn.l, insn.r, insn.d]:
        addr = op.global_address()
        if addr:
            print(f"0x{insn.ea:x}: {insn.opcode.name} refs 0x{addr:x}")

# 分析条件分支
for block in mba.blocks(skip_sentinels=True):
    if block.block_type == MicroBlockType.TWO_WAY:
        tail = block.tail
        print(f"条件 {tail.opcode.name} @ block {block.index}")
        print(f"  taken -> block {block.jump_target}")
        print(f"  fall  -> block {block.fall_through}")

# XOR 常量检测（可能为字符串解密）
for insn in mba.find_instructions(opcode=MicroOpcode.XOR):
    if insn.r.is_constant():
        const = insn.r.value()
        if 0x20 <= const <= 0x7E:  # 可打印 ASCII
            print(f"XOR 0x{const:02x} ('{chr(const)}') at 0x{insn.ea:x}")
```

### 编写微码优化器

```python
from ida_domain.microcode import (
    MicroInstructionOptimizer, MicroBlockOptimizer,
    MicroOpcode, MicroOperandType,
)

# 指令级优化
class MyInsnOptimizer(MicroInstructionOptimizer):
    def func(self, insn):
        if insn.opcode == MicroOpcode.ADD and insn.r.is_zero():
            # 将 add x, 0 替换为 mov
            insn.opcode = MicroOpcode.MOV
        return 0  # 0 = 继续

opt = MyInsnOptimizer()
mba.for_all_instructions(opt)

# 块级优化
class MyBlockOptimizer(MicroBlockOptimizer):
    def func(self, blk):
        # blk 是 mblock_t（原始的）
        return 0

# 清理死代码后的完整流程
from ida_domain.microcode import AnalyzeCallsFlags
mba = db.microcode.generate(func, maturity=MicroMaturity.LVARS)
mba.analyze_calls(AnalyzeCallsFlags.GUESS)
mba.for_all_instructions(MyInsnOptimizer())
```

## 伪代码 (Pseudocode)

```python
# 最简方式：直接拿文本行（推荐）
lines = db.pseudocode.get_text(func)         # List[str]，去掉 IDA 颜色标签
lines = db.pseudocode.get_text(func, remove_tags=False)  # 保留标签

# 完整反编译对象
pseudo = db.pseudocode.decompile(func)       # 等同于 db.functions.get_pseudocode(func)

# 文本输出
for line in pseudo.to_text():               # 行列表
    print(line)
```

### 属性

```python
pseudo.entry_ea          # 函数入口地址
pseudo.maturity          # PseudocodeMaturity 级别
pseudo.body              # PseudocodeInstruction（函数体 ctree 入口）
pseudo.mba               # 对应 MicroBlockArray
pseudo.header_lines      # 声明/头部的行数
```

### CTree 遍历

```python
# 遍历所有表达式节点
for expr in pseudo.walk_expressions():
    if hasattr(expr, 'op') and expr.op == PseudocodeExpressionOp.CALL:
        print(f"call: {expr}")

# 遍历所有顶层语句
for insn in pseudo.walk_instructions():
    print(f"instruction: {insn}")

# 遍历所有节点（表达式 + 语句）
for node in pseudo.walk_all():
    print(type(node).__name__)
```

### 查找方法

```python
pseudo.find_calls()                    # 所有调用表达式
pseudo.find_strings()                  # 所有字符串常量
pseudo.find_variables('var_name')      # 按名查找变量引用
pseudo.find_objects(0x1000)            # 所有全局对象引用
pseudo.find_assignments()              # 所有赋值
pseudo.find_if_instructions()          # 所有 if 语句
pseudo.find_loops()                    # 所有循环
pseudo.find_return_instructions()      # 所有 return 语句
pseudo.find_expression(PseudocodeExpressionOp.CALL)  # 按操作码查找
pseudo.find_instruction(PseudocodeInstructionOp.BLOCK)  # 按指令类型查找
pseudo.find_parent_of(node)            # 查找某节点的父节点
```

### 局部变量

```python
for lvar in pseudo.local_variables:
    print(f"{lvar.name}: size={lvar.width}, arg={lvar.is_arg}")
args = pseudo.arguments                 # 仅函数参数
lvar = pseudo.find_local_variable('a1')

# 修改变量并持久化
lvar.set_user_name('new_name')
lvar.set_type(tif)
pseudo.save_local_variable_info(lvar, save_name=True, save_type=True)
```

### 用户标注

```python
pseudo.add_comment(ea, 'decrypt loop')          # 在行尾添加注释
comment = pseudo.get_comment(ea)
pseudo.remove_comment(ea)

for label, ea in pseudo.user_labels():         # 用户标签
    pass
for ea, comment in pseudo.user_comments():     # 用户注释
    pass
for ea, flags in pseudo.user_iflags():         # 用户自定义标志
    pass
for ea, fmt in pseudo.user_numforms():         # 用户数字格式
    pass
```

### 修改与刷新

```python
# 修改 ctree 后
pseudo.verify()           # 验证 ctree 正确性
pseudo.refresh()          # 刷新伪代码文本（使修改生效）
pseudo.build_ctree()      # 重建 ctree
```

### CTree 关键类

| 类 | 说明 |
|---|---|
| `PseudocodeInstruction` | 一条语句（块、if、for、while、return 等） |
| `PseudocodeExpression` | 一个表达式（调用、赋值、运算符、变量、常量等） |
| `PseudocodeBlock` | 代码块 |
| `PseudocodeIf` | if 语句 |
| `PseudocodeFor` / `PseudocodeWhile` / `PseudocodeDo` | 循环语句 |
| `PseudocodeReturn` | return 语句 |
| `PseudocodeCallArg` | 调用参数 |

### 访问者模式

```python
from ida_domain.pseudocode import (
    PseudocodeExpressionVisitor, PseudocodeInstructionVisitor,
    PseudocodeVisitor, PseudocodeParentVisitor,
)

# 表达式访问者
class MyExprVisitor(PseudocodeExpressionVisitor):
    def visit_expr(self, expr):
        print(f"visiting: {expr}")
        return 0  # 0 = 继续遍历

visitor = MyExprVisitor()
pseudo.walk_expressions(visitor)
```

### 查找调用目标

```python
# 找到所有调用，提取目标
for expr in pseudo.find_calls():
    # expr.x 是调用目标表达式
    if expr.x.op == PseudocodeExpressionOp.OBJ:
        print(f"direct call to 0x{expr.x.obj_ea:x}")
    elif expr.x.is_var:
        print(f"indirect call via {expr.x.variable.name}")
```

### 语义查询

带完整参数签名的查询方法：

```python
# find_calls：可按目标名或目标地址过滤
calls = pseudo.find_calls()                          # 所有调用
calls = pseudo.find_calls(target_name='malloc')      # 按函数名过滤
calls = pseudo.find_calls(target_ea=0x401000)        # 按目标地址过滤

# find_strings：所有字符串常量表达式
strs = pseudo.find_strings()                         # List[PseudocodeExpression]

# find_variables：可按变量索引或变量名过滤
vars_ = pseudo.find_variables()                      # 所有变量引用
vars_ = pseudo.find_variables(var_name='v1')         # 按名过滤
vars_ = pseudo.find_variables(var_index=0)           # 按 lvars 索引过滤

# find_assignments：所有赋值表达式（is_assignment == True）
asgns = pseudo.find_assignments()                    # List[PseudocodeExpression]

# find_loops：for / while / do 语句
loops = pseudo.find_loops()                          # List[PseudocodeInstruction]

# find_if_instructions：所有 if 语句
ifs = pseudo.find_if_instructions()                  # List[PseudocodeInstruction]

# find_parent_of：查找某节点的父节点（表达式或语句均可）
parent = pseudo.find_parent_of(node)
# -> Optional[Union[PseudocodeExpression, PseudocodeInstruction]]
```

### 注释管理

```python
from ida_domain.pseudocode import CommentPlacement

# 添加/替换注释，默认挂在语句尾部分号处
pseudo.add_comment(expr.ea, 'decrypt routine')
pseudo.add_comment(expr.ea, 'branch taken',
                   placement=CommentPlacement.BLOCK1)

# 读取注释（返回 None 表示不存在）
text = pseudo.get_comment(expr.ea)                   # Optional[str]
text = pseudo.get_comment(expr.ea,
                          placement=CommentPlacement.SEMI)

# 删除注释
pseudo.remove_comment(expr.ea)
pseudo.remove_comment(expr.ea, placement=CommentPlacement.SEMI)

# 低级：通过上下文管理器访问原始映射
with pseudo.user_labels() as labels:       # user_labels_t: label_num -> name
    if labels:
        for org_label, name in labels.items():
            print(org_label, name)

with pseudo.user_comments() as cmts:      # user_cmts_t: treeloc_t -> comment
    if cmts:
        for loc, cmt in cmts.items():
            print(hex(loc.ea), cmt)

with pseudo.user_iflags() as iflags:      # user_iflags_t: citem_locator_t -> flags
    if iflags:
        for cl, f in iflags.items():
            print(hex(cl.ea), cl.op, f)

with pseudo.user_numforms() as numforms:  # user_numforms_t: operand_locator_t -> nf
    if numforms:
        for ol, nf in numforms.items():
            print(hex(ol.ea), ol.opnum, nf.flags)
```

### ctree 验证与刷新

```python
# 修改 ctree 后必须调用 refresh 以重新生成伪代码文本
pseudo.verify()                            # 检查 ctree 一致性，默认允许未使用的标签
pseudo.verify(allow_unused_labels=False)   # 严格模式：不允许未使用标签
pseudo.refresh()                           # 重新生成伪代码文本行
pseudo.build_ctree()                       # 从微码重建整个 ctree
```

## 事件钩子

```python
from ida_domain.hooks import DatabaseHooks, DecompilerHooks

class MyHooks(DatabaseHooks):
    def ev_rename(self, ea, new_name):
        print(f"rename 0x{ea:x} -> {new_name}")
        return 0  # 返回 0 允许操作继续

hooks = [MyHooks()]
with Database.open('/path/to/file.i64', hooks=hooks) as db:
    db.names.set_name(0x100001000, 'test')  # 触发钩子
```

可用钩子类：`ProcessorHooks`、`DatabaseHooks`、`UIHooks`、`ViewHooks`、`DebuggerHooks`、`DecompilerHooks`

## 异常体系

所有异常继承自 `IdaDomainError`：

| 异常 | 触发条件 |
|------|---------|
| `InvalidEAError` | 操作无效地址 |
| `InvalidParameterError` | 参数无效 |
| `DatabaseNotLoadedError` | 数据库未打开时操作 |
| `DatabaseError` | 数据库操作失败 |
| `NoValueError` | 读未初始化地址 |
| `UnsupportedValueError` | 不支持的格式 |
| `DecompilerError` | 反编译失败 |

```python
from ida_domain.base import InvalidEAError

try:
    name = db.names.get_at(0xDEADBEEF)
except InvalidEAError:
    print("无效地址")
```

## 与原生 SDK 混用

`ida-domain` 的对象直接传给原生 SDK：

```python
import ida_hexrays
import ida_bytes

# func_t 传给原生函数
cfunc = ida_hexrays.decompile(func.start_ea)

# insn_t 传给原生函数
for insn in db.functions.get_instructions(func):
    raw = ida_bytes.get_bytes(insn.ea, insn.size)

# ea_t 就是 int，直接使用
flags = ida_bytes.get_flags(0x100001000)
```

## 常见模式速查

### 遍历所有函数并获取反汇编

```python
for func in db.functions:
    lines = db.functions.get_disassembly(func)
```

### 查找所有调用某个 API 的位置

```python
api = db.imports.get_import_by_name('libc.so!malloc')
for src in db.xrefs.calls_to_ea(api.address):
    caller = db.functions.get_at(src)
    if caller:
        print(f"malloc called in {db.functions.get_name(caller)} at 0x{src:x}")
```

### 搜索常量/模式

```python
# 搜索立即数
ea = db.bytes.find_immediate_between(0xDEADBEEF)

# 搜索字节序列
addrs = db.bytes.find_binary_sequence(b'\x1f\x20\x03\xd5')  # ARM64 NOP

# 搜索字符串引用
for imp in db.imports.get_all_imports():
    if 'encrypt' in (imp.name or '').lower():
        for src in db.xrefs.calls_to_ea(imp.address):
            print(f"0x{src:x}")
```

### 重命名 + 批量

```python
for func in db.functions:
    if func.start_ea >= 0x100001000:
        db.functions.set_name(func, f'handler_{func.start_ea:x}')
```

## 常见陷阱

### 类型系统

```python
# ❌ 错误 — apply_at 的参数是 (tinfo_t, ea)，不是 (ea, string)
db.types.apply_at(ea, 'int func(void);')   # TypeError!

# ✅ 正确 — 字符串用这个
db.types.apply_declaration_at(ea, 'int func(void);')

# ✅ 正确 — 两步法（先解析再应用）
tif = db.types.parse_one_declaration(None, 'int func(void);')
db.types.apply_at(tif, ea)   # apply_at(tinfo_t, ea)
```

### MicroLocalVar: `is_arg` / `is_result` / `is_used` 是 property

```python
# ❌ 错误
lvar.is_arg()    # TypeError: 'bool' object is not callable

# ✅ 正确 — 不加括号
lvar.is_arg      # True / False
lvar.is_result
lvar.is_used
```

同理 `MicroInstruction.is_top_level` 也是 property。

### MemoryOperand.get_value() 返回值因架构而异

```python
# ❌ 脆弱 — 不是所有操作数都是纯立即数
op = db.instructions.get_operand(insn, 0)
print(hex(op.get_value()))   # ARM64 STP 的 MemoryOperand 返回 dict，会报错

# ✅ 正确 — 按子类判断
from ida_domain.operands import RegisterOperand, ImmediateOperand, MemoryOperand
if isinstance(op, ImmediateOperand):
    print(hex(op.get_value()))       # int
elif isinstance(op, MemoryOperand):
    print(op.get_address())          # ea_t
    print(op.get_displacement())     # int
elif isinstance(op, RegisterOperand):
    print(op.get_register_name())    # str
```

### `.is_call` 在不同上下文含义不同

```python
# XrefInfo.is_call — property（属性）
xref.is_call     # True/False，不加括号

# MicroInstruction.is_call — method（方法）
insn.is_call()   # True/False，要加括号

# MicroOpcode.is_call — property（枚举属性）
MicroOpcode.CALL.is_call   # True
```
