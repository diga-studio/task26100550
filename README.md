# zipgate — ZIP 文件入库核验库

对单个本地 ZIP 归档做结构伪造核验，返回**接收**或**隔离**结论及原因。
不修改原文件，不保存解压内容，不启动任何网络服务。

## 用法

```python
import zipgate

verdict = zipgate.verify_archive("/path/to/archive.zip")
if verdict.accepted:
    ...  # 接收：verdict.decision is zipgate.Decision.ACCEPT
else:
    ...  # 隔离：verdict.reason 给出中文原因
```

`verify_archive(path)` 返回 `Verdict(decision, reason)`：

- `decision`：`Decision.ACCEPT` 或 `Decision.QUARANTINE`
- `accepted`：布尔便捷属性
- `reason`：结论原因（接收时为通过说明，隔离时为具体违规点）

结论针对整个归档：任何条目失败都返回隔离，不存在部分接收。

## 核验规则摘要

- 仅接收单卷 ZIP32：stored / deflate，通用标志仅允许位 3（数据描述符）与位 11（UTF-8）。
- 加密、ZIP64、多卷、其他压缩方法一律隔离；未知附加字段允许但必须结构完整。
- 中央目录与本地条目一一对应，文件名原始字节、方法、标志一致；目录顺序可与本地顺序不同。
- 数据描述符有/无签名两种形式均支持，CRC32 等于描述符签名时也能唯一解析。
- 文件必须恰好由 本地条目序列 + 中央目录 + EOCD（含声明的归档注释）组成，无前置、空洞、重叠或尾随内容；注释中的伪 EOCD 不遮蔽真正的结束记录。
- 逐条目核对真实解压内容的 CRC32 与字节数；deflate 数据区必须恰好是一个完整流（截断、拼接、夹带整字节均隔离，末字节填充位除外）。
- 全部条目展开总量上限 1 GiB，恰好达到可接收，超过即隔离并停止展开。

## 非功能特性

- 核验全程流式读写：单次读块 1 MiB，解压输出单次限 1 MiB，除解释器基线外峰值内存远低于 64 MiB，高压缩率输入同样满足。
- 设计输入规模：单归档 500 MiB、最多 50000 条目。

## 运行测试

```bash
python3 -m pytest tests -q
```

覆盖：不同目录顺序、两种数据描述符、伪 EOCD 注释、CRC32 等于描述符签名、
目录/本地头矛盾、共用本地条目、deflate 夹带、1 GiB 展开边界、高压缩率内存约束、
5 万条目等场景。
