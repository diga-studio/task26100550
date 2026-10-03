# zipvet — ZIP 入库核验库

在归档进入存储前做结构伪造拦截：只核验 ZIP，返回**接收**或**隔离**结论及原因。
全程只读输入文件，不修改原文件，也不保存任何解压内容。

## 用法

```python
from zipvet import verify_zip, Decision

verdict = verify_zip("/path/to/archive.zip")
if verdict.decision is Decision.ACCEPT:
    ...  # 放行入库
else:
    print(verdict.reason)  # 隔离原因
```

`verify_zip(path)` 返回 `Verdict`：

- `verdict.decision`：`Decision.ACCEPT` 或 `Decision.QUARANTINE`
- `verdict.accepted`：布尔便捷属性
- `verdict.reason`：结论原因（中文描述）

## 核验规则（摘要）

- 仅接收单卷 ZIP32，压缩方法限 stored / deflate，通用标志仅允许位 3、位 11；
  加密、ZIP64、多卷一律隔离。附加字段允许未知类型，但每条必须完整。
- 中央目录与本地条目一一对应：文件名原始字节、方法、标志一致；
  未启用数据描述符时本地头 CRC/大小须与目录一致，启用时各字段允许为零或一致，
  且描述符（含 CRC32 等于描述符签名的情形，有/无签名两种形式）须与目录一致。
- 文件起点到中央目录必须恰好由完整、互不重叠的本地条目组成；
  中央目录之后只允许 EOCD 及其声明的归档注释；拒绝前置内容、空洞、重叠、尾随。
  归档注释中的伪 EOCD 不遮蔽真正的结束记录；全文件须只有唯一有效解析。
- 逐条目解压核对真实 CRC32 与字节数；deflate 压缩区必须恰好是一个完整流
  （截断、拼接、流后整字节夹带均隔离，末字节内填充位不算夹带）。
- 全部条目展开总量上限 1 GiB，恰好达到可接收，超过即隔离并停止展开。
- 核验为流式处理，额外峰值内存不超过 64 MiB。

## 运行测试

```bash
python3 -m pytest tests/ -q
```
