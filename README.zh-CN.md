# sbom-change-review

在发版前检查组件和许可证变化。直接读取 CycloneDX JSON 1.5/1.6、SPDX JSON 2.3，生成完全离线、可搜索的 HTML 报告，也可输出 JSON、Markdown。

```sh
python -m pip install .
python -m sbom_change_review demo --output report.html
sbom-change-review compare baseline.json current.json --deny-license GPL-3.0-only --deny-new --deny-unknown-license --output review.html
```

要求 Python 3.10+，无运行时依赖。安装后 demo 可在任意目录运行，使用包内明确标注为虚构的示例；不会联网或上传文件。

身份优先使用去掉版本的 purl，保留命名空间、qualifier 和子路径；无 purl 时按精确 group/name 匹配，不跨文件直接匹配 bom-ref。单版本一对一匹配才报告版本/许可证变化；多版本或重复记录全部保留，无法唯一对应时标为 ambiguous，不猜测升级关系。JSON 包含完整前后记录。

退出码：0=所选策略通过，1=策略失败但仍生成报告，2=输入或输出错误。默认没有阻断政策。`--deny-new` 阻止新组件身份，`--deny-license` 可重复，`--deny-unknown-license` 阻止未知许可证，`--deny-ambiguous` 阻止无法唯一对应的变化。策略检查当前清单，不只检查新增项。`MIT OR GPL-3.0-only` 包含被禁止标识时会保守提示人工评审，不解释许可证法律义务。

CycloneDX CLI 已经支持 diff；本项目的重点是发版策略和可审阅证据，不是漏洞扫描器。只验证受支持字段，不提供完整 schema 校验、签名验证、依赖解析或合规认证。缺少版本保持 unknown，不当成 0。完整字段范围、SPDX 许可证优先级和限制见 [英文说明](README.md)。

运行测试：`python -m unittest discover -s tests -v`。欢迎提交脱敏后的真实工具导出样本和可复现问题。MIT 许可证。
