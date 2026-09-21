# sing-box-geosite

在 `url.yaml` 中按分组添加规则集 URL，运行 `python main.py` 后，每组会在 `rule-set/` 下生成同名的 `.json`、`.srs` 和 `.list` 文件。来源可以是 `.list`、`.yaml` 或 `.txt`；重复规则会合并。

`.json` 和 `.srs` 用于 sing-box，`.list` 是 Surge 的外部规则集。Surge 配置示例：

```text
[Rule]
RULE-SET,https://raw.githubusercontent.com/<用户名>/<仓库>/main/rule-set/domestic.list,DIRECT
```

某个来源下载失败时会跳过并打印告警；如果一个分组没有任何可用规则，该分组会保留已有产物并让任务报错。

仓库 Settings ----> Actions ----> General ----> Workflow permissions ----> Read and write permissions 勾选上

sing-box 规则集引用示例：

```json
{
  "tag": "domestic",
  "type": "remote",
  "format": "source",
  "url": "https://raw.githubusercontent.com/<用户名>/<仓库>/main/rule-set/domestic.json",
  "download_detour": "auto"
}
```

# 致谢（排名不分先后）

[@izumiChan16](https://github.com/izumiChan16)

[@ifaintad](https://github.com/ifaintad)

[@NobyDa](https://github.com/NobyDa)

[@blackmatrix7](https://github.com/blackmatrix7)

[@DivineEngine](https://github.com/DivineEngine)
