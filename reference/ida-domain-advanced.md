# ida-domain 进阶：Pseudocode CTree & Microcode 深层 API

> 本文档是 `reference/ida-domain.md` 的补充，覆盖 Pseudocode CTree 操作和 Microcode 修改/分析的高级 API。

## 目录

**Part A — Pseudocode CTree**
1. [PseudocodeFunction 进阶](#a1-pseudocodefunction-进阶)
2. [表达式修改与查询](#a2-表达式修改与查询)
3. [语句子类详解](#a3-语句子类详解)
4. [调用参数](#a4-调用参数)
5. [数值常量 PseudocodeNumber](#a5-数值常量-pseudocodenumber)

**Part B — Microcode 深层**
6. [微码修改](#b1-微码修改)
7. [控制流图编辑](#b2-控制流图编辑)
8. [操作数变换](#b3-操作数变换)
9. [调用信息 MicroCallInfo](#b4-调用信息-microcallinfo)
10. [位置集合 MicroLocationSet](#b5-位置集合-microlocationset)
11. [使用-定义链 MicroGraph](#b6-使用-定义链-micrograph)
12. [成熟度推进流水线](#b7-成熟度推进流水线)

---

# Part A — Pseudocode CTree

## A1. PseudocodeFunction 进阶

基础用法（反编译、遍历、查找）见主文档。以下是进阶操作。

### 表达式替换与修改

```python
pseudo = db.pseudocode.decompile(func)

# 遍历并替换特定表达式
for expr in pseudo.walk_expressions():
    # 将所有常量 0xDEAD 替换为 0
    if expr.op == PseudocodeExpressionOp.NUM and expr.number == 0xDEAD:
        new_expr = PseudocodeExpression.from_number(0)
        expr.replace_with(new_expr)

    # 逻辑取反某个条件
    if expr.is_nice_cond:  # 是否可作为布尔条件（属性）
        expr.negate()      # 原地取反

pseudo.verify()   # 验证修改后 ctree 正确性
pseudo.refresh()  # 刷新伪代码文本
```

### 表达式语义查询

```python
# 检查是否包含特定操作符
if expr.contains_operator(PseudocodeExpressionOp.CALL):
    print("表达式树中含有调用")

# 检查语义等价
if expr.equal_effect(other_expr):
    print("两个表达式语义等价")

# 设置类型
expr.set_type(some_tinfo_t)
```

### 工厂方法

```python
# 从头创建表达式节点
num = PseudocodeExpression.from_number(42)          # 常量 42
s = PseudocodeExpression.from_string("hello")        # 字符串常量
obj = PseudocodeExpression.from_object(0x1000)       # 全局对象引用
var = PseudocodeExpression.from_variable(lvar)       # 局部变量引用
helper = PseudocodeExpression.from_helper("HIWORD")  # helper 调用
unary = PseudocodeExpression.from_unary(
    PseudocodeExpressionOp.NEG, num                  # -42
)
binary = PseudocodeExpression.from_binary(
    PseudocodeExpressionOp.ADD, num, num             # 42 + 42
)
call = PseudocodeExpression.from_call(
    target_expr, [arg1, arg2]                       # target(arg1, arg2)
)
```

### PseudocodeInstruction 进阶

```python
# 遍历语句内的所有表达式
for insn in pseudo.walk_instructions():
    for expr in insn.walk_expressions():
        pass

# 类型详情（按语句类型返回对应详情对象）
if insn.is_block:
    details = insn.block   # PseudocodeBlock
elif insn.is_if:
    details = insn.if_details      # PseudocodeIf  (condition, then, else)
elif insn.is_for:
    details = insn.for_details     # PseudocodeFor (init, condition, step, body)
elif insn.is_while:
    details = insn.while_details   # PseudocodeWhile (condition, body)
elif insn.is_do:
    details = insn.do_details      # PseudocodeDo (body, condition)
elif insn.is_switch:
    details = insn.switch_details  # PseudocodeSwitch (expression, cases)
elif insn.is_return:
    details = insn.return_details  # PseudocodeReturn (expression)
elif insn.is_goto:
    details = insn.goto_details    # PseudocodeGoto (label_num)

# 普通流控制检查
if insn.is_ordinary_flow():
    print("非分支指令")
```

---

## A2. 表达式修改与查询

### 核心修改方法

| 方法 | 说明 |
|------|------|
| `expr.replace_with(new_expr)` | 原地替换为另一个表达式 |
| `expr.negate()` | 逻辑取反（`x > 0` → `x <= 0`） |
| `expr.set_type(tinfo)` | 设置类型并连锁更新子节点 |

### 核心查询方法

| 方法 | 说明 |
|------|------|
| `expr.contains_operator(op, times=1)` | 表达式树中是否包含指定操作符 |
| `expr.contains_comma(times=1)` | 是否包含逗号操作符 |
| `expr.equal_effect(other)` | 语义等价比较 |
| `expr.is_nice_cond` | 是否可作为合法的布尔条件（属性） |
| `expr.has_side_effects()` | 是否有副作用 |

### 操作数访问

```python
expr.x   # 左操作数（如赋值目标、调用目标）
expr.y   # 右操作数（如赋值源、二元运算符右侧）
expr.z   # 第三操作数（如三元表达式的 else 分支）
expr.a   # 附加操作数（如 cast 的类型引用）
```

---

## A3. 语句子类详解

### PseudocodeBlock

```python
block = insn.block   # 如果 insn.is_block

len(block)                   # 语句数
for stmt in block:           # 迭代语句
    pass
block[0]                     # 按索引访问
block.first                  # 第一条语句
block.last                   # 最后一条语句
block.is_empty               # 是否空块
block.append(new_stmt)       # 追加语句
block.remove(stmt)           # 移除语句
```

### PseudocodeIf

```python
if_stmt = insn.if_details

if_stmt.condition            # 条件表达式
if_stmt.then_branch          # then 块 (PseudocodeInstruction)
if_stmt.else_branch          # else 块，可能为 None
if_stmt.has_else             # 是否有 else
if_stmt.swap_branches()      # 交换 then/else 并取反条件
```

### PseudocodeFor

```python
for_stmt = insn.for_details

for_stmt.init                # 初始化表达式（如 i = 0）
for_stmt.condition           # 循环条件（如 i < 10）
for_stmt.step                # 递增表达式（如 i++）
for_stmt.body                # 循环体 (PseudocodeInstruction)
```

### PseudocodeWhile / PseudocodeDo

```python
while_stmt = insn.while_details
while_stmt.condition          # 条件
while_stmt.body               # 循环体

do_stmt = insn.do_details
do_stmt.body                  # 循环体（先执行）
do_stmt.condition             # 条件（后判断）
```

### PseudocodeSwitch

```python
switch = insn.switch_details

switch.expression             # switch 的表达式
for case in switch:           # 迭代所有 case
    if case.is_default:
        print("default:")
    else:
        print(f"case {case.values}:")
    for stmt in case.body:    # case 体中的语句
        print(f"  {stmt}")
```

### PseudocodeCase

```python
case.values                   # 值列表（如 [1, 2, 3]），空列表 = default
case.is_default               # 是否 default 分支
case.body                     # case 体 (PseudocodeInstruction)
```

### PseudocodeReturn

```python
ret = insn.return_details
ret.expression                # 返回值表达式，void 返回时为 None
```

### PseudocodeGoto

```python
goto = insn.goto_details
goto.label_num                # 目标标签编号
```

### PseudocodeTry / PseudocodeThrow

```python
try_stmt = insn.try_details
try_stmt.body                 # try 体

throw = insn.throw_details
throw.expression              # 抛出的异常表达式
```

---

## A4. 调用参数

```python
# 获取调用的参数列表
call_expr = pseudo.find_calls()[0]
args = call_expr.a            # PseudocodeCallArgList

len(args)                     # 参数数量
for arg in args:              # 迭代参数
    print(arg.expression)     # 参数表达式 (PseudocodeExpression)
    print(arg.is_vararg)      # 是否可变参数
    print(arg.formal_type)    # 函数原型中的形式类型
```

---

## A5. 数值常量 PseudocodeNumber

```python
# expr.number 是 PseudocodeNumber（当 expr.op == NUM 时）
num = expr.number

num.value                     # 符号扩展后的值
num.unsigned_value            # 原始 64 位无符号值
num.typed_value(tinfo)        # 按指定类型解释的值

# 支持数值协议
num == 0                      # 直接比较
num + 1                       # 算术运算

# 格式定制
num.number_format             # 显示格式
```

---

# Part B — Microcode 深层

## B1. 微码修改

### MicroInstruction 修改

```python
from ida_domain.microcode import MicroOpcode, MicroInstruction

insn = list(mba.instructions())[0]

# 转为 NOP
insn.make_nop()

# 原地替换
new_insn = MicroInstruction.create(MicroOpcode.MOV)
new_insn.l.set_register(0, 8)
new_insn.d.set_register(1, 8)
insn.replace_with(new_insn)

# 交换两条指令
insn1.swap(insn2)

# 单指令优化
insn.optimize_solo()
```

### 指令标志查询 / 设置

```python
# 查询（均为 property）
insn.is_assert              # 断言指令
insn.is_persistent          # 持久指令
insn.is_combinable          # 可组合
insn.is_optional            # 可选
insn.is_tailcall            # 尾调用
insn.is_farcall             # 远调用
insn.is_cleaning_pop        # 清理栈的调用
insn.is_alloca              # alloca 调用
insn.is_memory_barrier      # 内存屏障
insn.is_bswap               # 字节交换
insn.is_memcpy / is_memset  # 内存操作
insn.is_readflags           # 读标志位
insn.is_inverted_jump       # 取反跳转
insn.is_wild_match          # 通配匹配
insn.is_unknown_call        # 未知调用

# 设置 / 清除（成对）
insn.set_combined() / insn.clr_combined()
insn.set_farcall() / insn.clr_farcall()
insn.set_tailcall() / insn.clr_tailcall()
insn.set_noret_icall() / insn.clr_noret_icall()
insn.set_memory_barrier()
insn.set_inverted_jump()
# ... 大部分标志有对应的 set_ / clr_ 方法
```

### 创建新指令与操作数

从头构建微码指令需要分配寄存器、创建操作数、组装指令三步。

```python
from ida_domain.microcode import MicroOperand, MicroInstruction, MicroOpcode

# 1. 分配临时寄存器
r0 = mba.alloc_kernel_register(size=8, check_size=True)
r1 = mba.alloc_kernel_register(size=8, check_size=True)

# 2. 创建操作数（均为 @staticmethod）
src = MicroOperand.number(42, size=4)             # 立即数 42
dst = MicroOperand.reg(r0, size=8)                # 临时寄存器
addr = MicroOperand.global_addr(0x1000, size=4)   # 全局地址
h = MicroOperand.helper("HIWORD")                 # helper 名
ref = MicroOperand.new_block_ref(serial=3)        # 基本块引用
pair = MicroOperand.reg_pair(loreg=0, hireg=1, halfsize=4)  # 寄存器对
empty = MicroOperand.empty()                      # 空操作数
# MicroOperand.stack_var(mba, offset=0x10)        # 栈变量
# MicroOperand.local_var(mba, idx=0, off=0)       # 局部变量
# MicroOperand.fpnum(b'\x00\x00\x80\x3f')         # 浮点常量

# 3. 创建指令
insn = MicroInstruction.create(MicroOpcode.MOV)
insn.l = src
insn.d = dst

# 4. 虚构地址（给新指令一个唯一地址）
fake_ea = mba.alloc_fictional_address(real_ea=0x40000)

# 5. 释放临时寄存器（不再使用时）
mba.free_kernel_register(r0, size=8)
mba.free_kernel_register(r1, size=8)
```

**操作数 setter**（修改已有操作数，而非创建新对象）：

```python
op.set_number(42, size=4, ea=0x40000)
op.set_register(mreg=0, size=8)
op.set_helper("HIWORD")
op.set_block_ref(serial=2)
op.set_global_addr(0x1000, size=4)
```

### 缓存与验证

修改微码后必须做的清理步骤：

```python
mba.mark_chains_dirty()          # 标记 use-def 链为脏（修改指令/操作数后）
mba.build_graph()                # 重建控制流图（增删块后）
mba.verify(always=True)          # 全量验证（always=False 时仅调试模式检查）
mba.remove_empty_and_unreachable_blocks()  # 清理死块
mba.merge_blocks()               # 合并相邻线性块
```

### 栈偏移转换

```python
# 反编译器栈偏移 ↔ IDA 栈偏移
ida_off = mba.stack_offset_decompiler_to_ida(decompiler_offset)
decompiler_off = mba.stack_offset_ida_to_decompiler(ida_off)
```

### 额外指令标志

```python
insn.is_bswap              # 字节交换指令（如 BSWAP）
insn.is_memcpy / insn.is_memset  # 内存复制 / 填充
insn.is_readflags          # 读标志位
insn.is_like_move          # 类似 MOV 的指令
insn.is_memory_barrier     # 内存屏障
insn.is_noret_call(flags)  # 不返回的调用（可传检查标志）
insn.is_cleaning_pop       # 调用后清理栈
```

### 前驱/后继序列号

```python
# 序列号列表（比迭代 successors() 更轻量）
block.successor_serials      # [2, 5, 7]
block.predecessor_serials    # [0, 3]
```

---

## B2. 控制流图编辑

### MicroBlockArray 块操作

```python
# 插入 / 删除块
new_block = mba.insert_block(index=3)

mba.remove_block(block)
mba.remove_blocks(start_index, end_index)

# 分裂块
mba.split_block(block, start_insn)  # 从指定指令处分裂

# 复制块
from ida_domain.microcode import CopyBlockFlags
mba.copy_block(source_block, new_serial=2, flags=CopyBlockFlags.MINREF)  # new_serial 须 <= 当前块数

# 清理
mba.remove_empty_and_unreachable_blocks()
mba.merge_blocks()       # 合并线性流中的连续块

# 验证
mba.verify(always=True)   # always=True 在每次调用时强制检查
```

### MicroBlock 图导航与编辑

```python
# 前驱 / 后继
for succ in block.successors():
    print(f"  -> block {succ.index}")

for pred in block.predecessors():
    print(f"  <- block {pred.index}")

block.successor_count
block.predecessor_count

# 边编辑
block.add_successor(target_block)
block.remove_successor(target_block)
block.clear_successors()
block.clear_predecessors()

# 序列号列表（适合批量处理）
serials = block.successor_serials   # [2, 5]
```

### MicroBlock 指令操作

```python
# 使用-定义链
block.build_use_list(insn)   # 该指令使用了哪些位置
block.build_def_list(insn)   # 该指令定义了哪些位置

# 将指令转为 NOP
block.make_nop(insn)

# 检查
block.contains_instruction(insn)  # insn 是否在此块中
```

---

## B3. 操作数变换

```python
op = insn.d

# 半字提取
op.make_low_half(width=4)     # 取低 4 字节
op.make_high_half(width=4)    # 取高 4 字节
op.make_first_half(width=4)   # 取前半
op.make_second_half(width=4)  # 取后半

# 大小变换
op.change_size(8)             # 改变大小
op.double_size()              # 翻倍大小
op.apply_zero_extension(8)    # 零扩展
op.apply_sign_extension(8)    # 符号扩展

# 常量偏移
op.shift_operand(4)           # 将常量操作数偏移

# 清除
op.clear()                    # 重置为空操作数
op.erase_but_keep_size()      # 清除但保留大小信息

# 扩展检查
op.is_sign_extended_from(4)   # 是否从 4 字节符号扩展而来
op.is_zero_extended_from(4)   # 是否从 4 字节零扩展而来
```

### 操作数类型检查（进阶）

```python
op.is_kernel_register         # 临时内核寄存器（属性）
op.is_condition_code          # 条件码寄存器（属性）
op.is_bit_register            # 位寄存器（含条件码）（属性）
op.is_scattered               # 分散操作数（属性）
op.is_boolean                 # 只能为 0 或 1（属性）
op.is_sub_instruction()       # 包含子指令（mop_d）
op.is_sub_instruction(MicroOpcode.XOR)  # 包含特定 opcode 的子指令
op.may_use_aliased_memory()   # 可能引用别名内存
```

### 获取栈变量

```python
result = op.get_stack_variable()
if result:
    frame_index, ida_offset = result  # (帧索引, IDA 栈偏移)
```

---

## B4. 调用信息 MicroCallInfo

```python
# 从 CALL 指令的操作数获取
insn = list(mba.find_instructions(opcode=MicroOpcode.CALL))[0]
ci = insn.l.call_info           # MicroCallInfo

# 基本信息
ci.callee                       # 目标地址
ci.fixed_arg_count              # 固定参数数量
ci.calling_convention           # 调用约定编号
ci.return_type                  # 返回类型 (tinfo_t)
ci.return_argloc                # 返回值位置
ci.role                         # FunctionRole 枚举（如 MEMSET, MEMCPY, STRLEN）
ci.flags                        # CallInfoFlags 位标志
ci.call_stack_pointer_delta     # 调用前后的 SP 变化
ci.stack_args_top               # 栈参数顶部偏移

# 判决
ci.is_vararg()                  # 可变参数?
ci.is_noret()                   # 不返回?
ci.is_pure()                    # 纯函数?

# 寄存器信息（均为 MicroLocationSet）
ci.spoiled                      # 被破坏的寄存器
ci.dead_regs                    # 死寄存器
ci.return_regs                  # 返回寄存器
ci.pass_regs                    # 传参寄存器
ci.visible_memory               # 可见内存范围 (ivlset_t)

# 参数操作
ci.add_arg()                    # 添加参数 → MicroCallArg
ci.clear_args()                 # 清除所有参数
ci.set_type(tinfo)              # 设置函数类型

# 参数遍历
for arg in ci.args:
    print(arg.name)             # 参数名
    print(arg.type)             # 参数类型 (tinfo_t)
    print(arg.size)             # 参数大小
    arg.set_reg_arg(mreg=0, arg_size=8, type_info=tinfo)  # 设为寄存器参数
    arg.make_string("hello")    # 设为字符串参数
    arg.make_number(42, nbytes=4)  # 设为数字参数
    arg.operand                 # 参数作为 MicroOperand
```

---

## B5. 位置集合 MicroLocationSet

```python
from ida_domain.microcode import MicroLocationSet

# 从 MicroCallInfo 获取
locs = ci.spoiled               # 被调用破坏的寄存器集合

# 迭代集合中的位置
for loc in locs:
    print(loc)                  # 每个位置是 vivl_t

# 集合操作
locs.count                      # 是否为空（属性，0 = 空）
locs.has_register(mreg, size)   # 是否包含某寄存器
locs.has_memory()               # 是否包含内存位置
locs.add_register(mreg, size)   # 添加寄存器
locs.add(other_set)             # 合并另一个集合
locs.subtract_register(mreg, size)  # 删除寄存器
locs.subtract(other_set)        # 差集
locs.clear()                    # 清空

# 集合间操作
locs.intersect(other_set)       # 交集
locs.unite(other_set)           # 并集
locs.subtract(other_set)        # 差集
locs.is_subset_of(other_set)    # 子集判断
locs.equal(other_set)           # 相等判断

# 内存范围
locs.include_memory()           # 包含所有内存位置
locs.exclude_memory()           # 排除内存位置
locs.has_memory()               # 是否包含内存
```

---

## B6. 使用-定义链 MicroGraph

```python
graph = mba.get_graph()

# 使用-定义链：给定一个使用点，找到所有可能定义该值的位置
chains = graph.get_use_def_chains(insn, operand_index=1)
for def_insn, def_op_num in chains:
    print(f"  0x{def_insn.ea:x} operand {def_op_num}")

# 定义-使用链：给定一个定义点，找到所有使用该值的位置
chains = graph.get_def_use_chains(insn, operand_index=0)
for use_insn, use_op_num in chains:
    print(f"  0x{use_insn.ea:x} operand {use_op_num}")

# 给定地址处的全局重定义
redefs = graph.get_redefines(0x1000)      # 所有重定义该全局变量的指令

# 给定地址处的全局使用
uses = graph.get_uses(0x1000)             # 所有使用该全局变量的指令

# 给定地址处的间接访问
indirect = graph.get_indirects(0x1000)    # 间接引用
```

---

## B7. 成熟度推进流水线

```python
from ida_domain.microcode import MicroMaturity

# 生成微码（初始成熟度）
mba = db.microcode.generate(func, maturity=MicroMaturity.GENERATED)

# 逐步推进
mba.set_maturity(MicroMaturity.LOCOPT)
mba.optimize_local(locopt_level=1)        # 局部优化

mba.set_maturity(MicroMaturity.CALLS)
mba.analyze_calls(AnalyzeCallsFlags.GUESS) # 分析调用约定

mba.set_maturity(MicroMaturity.GLBOPT1)
mba.optimize_global()                     # 全局优化

mba.set_maturity(MicroMaturity.LVARS)
mba.alloc_local_variables()               # 分配局部变量
mba.build_graph()                         # 重建控制流图
mba.verify(always=True)

# 此时 mba.vars 可用
print(len(mba.vars))

# 缓存清理（修改后）
mba.mark_chains_dirty()                   # 标记使用-定义链为脏

# 地址 / 位置转换
ida_offset = mba.stack_offset_decompiler_to_ida(decompiler_offset)
decompiler_offset = mba.stack_offset_ida_to_decompiler(ida_offset)
location = mba.location_ida_to_decompiler(ida_location)
```

---

## 扩展工具类速览

| 类 | 用途 | 何时用 |
|---|---|---|
| `MicroInstructionOptimizer` | 指令级优化器基类，override `optimize()` 和 `install()` | 自定义优化 pass |
| `MicroBlockOptimizer` | 块级优化器基类，override `optimize()` 和 `install()` | 块级优化 pass |
| `MicrocodeLifter` | 自定义指令 lifter，支持非标准 ISA 扩展。override `match()` / `apply()` | 处理器扩展 |
| `MicrocodeFilter` | 用户自定义调用过滤器，将指令模式转为函数调用 | 去混淆 |

---

## Microcode 高级操作

### MicroInstruction 导航与查询

#### 链表导航

```python
# 在块内的指令链表中前后移动
prev_insn = insn.prev   # Optional[MicroInstruction]，块头时为 None
next_insn = insn.next   # Optional[MicroInstruction]，块尾时为 None

# 遍历整个块（借助链表导航）
cur = block.head
while cur is not None:
    print(cur)
    cur = cur.next
```

#### 调用相关查询

```python
# 检查此指令（及其所有子指令）是否包含调用
if insn.contains_call(with_helpers=False):
    print("包含调用")

# 在指令树中查找第一个 CALL/ICALL 子指令
call_sub = insn.find_call(with_helpers=False)
# 返回 Optional[MicroInstruction]；with_helpers=True 时也匹配 helper 调用

# 查找具有指定 opcode 的第一个子指令
sub = insn.find_opcode(MicroOpcode.XOR)   # Optional[MicroInstruction]

# 查找数字操作数（l 或 r 中的立即数）
result = insn.find_numeric_operand()
# 返回 Optional[Tuple[MicroOperand, MicroOperand]]
# (num_operand, other_operand) — num 是数字操作数，other 是另一侧；两者都不是数字时返回 None
if result:
    num_op, other_op = result
    print(f"立即数值: {num_op.value}")
```

---

### MicroBlock 分析

```python
# 向后查找最近一条定义 operand 的指令
# 从 start（不含）向块头扫描；start=None 从块尾开始
def_insn = block.find_def_backward(
    operand=insn.d,
    start=insn,          # Optional[MicroInstruction]
)
# 仅支持 mop_r（寄存器）、mop_S（栈变量）、mop_l（局部变量）
# 返回 Optional[MicroInstruction]

# 查找 start 之后首次使用 locations 的指令
# 注意：locations 会被原地修改（被重定义的位置从集合中删除），需要保留原集合时先 copy()
locs = MicroLocationSet()
locs.add_register(op.register, op.size)  # 添加寄存器位置
first_use = block.find_first_use(
    locations=locs,
    start=some_insn,
    end=None,            # Optional[MicroInstruction]，None = 搜索到块尾
)
# 返回 Optional[MicroInstruction]

# 检查 insn 的右侧操作数（源操作数）在 [start, end) 范围内是否被重定义
redefined = block.is_rhs_redefined(
    insn=target_insn,
    start=start_insn,
    end=None,            # Optional[MicroInstruction]，None = 到块尾
)
# 返回 bool
```

---

### MicroBlockArray 编辑补充

```python
from ida_domain.microcode import CopyBlockFlags

# 复制一个块并插入到指定序列号位置
new_block = mba.copy_block(
    source=block,
    new_serial=2,                    # 必须 <= 当前块数量
    flags=CopyBlockFlags.MINREF,     # MINREF 或 OPTJMP，无 FAST
)
# 返回 MicroBlock

# 在指定索引处插入一个全新的空块
new_block = mba.insert_block(index=3)   # 返回 MicroBlock

# 删除一个块
changed = mba.remove_block(block)   # 返回 bool（True = 有其他块因此变为空/不可达）
```

```python
from ida_domain.microcode import MicroInstructionOptimizer, MicroOpcode

class MyOptimizer(MicroInstructionOptimizer):
    def optimize(self, insn):
        # 将 x ^ x 优化为 0
        if insn.opcode == MicroOpcode.XOR and insn.l == insn.r:
            # 用 MOV 替换
            insn.opcode = MicroOpcode.MOV
            return True   # 报告做了更改
        return False       # 未更改

    def install(self):
        # 检查是否可安装此优化器
        return True

opt = MyOptimizer()
mba.for_all_instructions(opt)
mba.verify()
```

---

## 与主文档的关系

主文档 `reference/ida-domain.md` 覆盖日常必用 API（~90%）。本文档覆盖 Pseudocode CTree 和 Microcode 的深层操作：

| 内容 | 主文档 | 本文档 |
|------|--------|--------|
| 伪代码反编译 / 文本 / 遍历 | ✅ | — |
| 伪代码查找 (find_*) | ✅ | — |
| **表达式替换 / 语义查询** | — | ✅ A2 |
| **5 个语句子类详细属性** | — | ✅ A3 |
| **调用参数 / 数值常量** | — | ✅ A4-A5 |
| 微码生成 / 遍历 / Opcode | ✅ | — |
| **微码修改 (make_nop / replace_with)** | — | ✅ B1 |
| **指令标志设置 / 清除** | — | ✅ B1 |
| **块级图编辑 (insert / split / successors)** | — | ✅ B2 |
| **操作数变换 (make_low_half / shift)** | — | ✅ B3 |
| **MicroCallInfo 调用详情** | — | ✅ B4 |
| **MicroLocationSet / MicroGraph** | — | ✅ B5-B6 |
| **成熟度推进 / 优化流水线** | — | ✅ B7 |
