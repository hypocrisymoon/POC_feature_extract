# AI驱动的PCAP漏洞分析工具

这是一个基于人工智能的网络安全分析工具，能够从PCAP数据包中提取网络流量信息，并利用AI模型进行智能化的漏洞识别和安全分析。该工具特别适用于安全研究、渗透测试和漏洞挖掘场景。

## 项目概述

本项目的核心工作流程：
1. **数据提取**：从PCAP文件中提取HTTP/HTTPS请求、响应和载荷数据
2. **特征分析**：解析网络流量中的关键安全特征
3. **AI分析**：将提取的数据发送给AI模型进行漏洞分析
4. **结果输出**：生成详细的安全分析报告和漏洞识别结果

## 功能特性

### 网络流量分析
- 提取HTTP/HTTPS请求和响应信息
- 解析请求方法、路径、头部信息
- 提取完整的payload数据和攻击载荷
- 支持批量处理多个PCAP文件
- **支持命令行参数指定任意路径的PCAP文件**
- **自动处理相对路径和绝对路径**

### AI智能分析
- **集成AI模型进行漏洞自动识别**
- **智能分析攻击模式和恶意载荷**
- **生成详细的安全分析报告**
- **支持多种漏洞类型检测（RCE、注入、反序列化等）**

### 输出格式
- CSV格式：适合数据分析和统计
- JSON格式：适合程序化处理和API集成
- AI分析报告：包含漏洞评估和安全建议

## 安装依赖

```bash
pip install -r requirements.txt
```

### 主要依赖包
- `scapy`: PCAP文件解析和网络包分析
- `openai`: AI模型API调用
- `pandas`: 数据处理和分析
- `requests`: HTTP请求处理

### AI模型配置
1. 配置OpenAI API密钥或兼容的AI服务
2. 修改 `api.py` 中的API配置
3. 确保有足够的API调用额度

## 使用方法

### 1. 快速开始 - 分析单个PCAP文件

```bash
# 分析指定路径的PCAP文件
python run_analysis.py attack_sample.pcap

# 使用绝对路径
python run_analysis.py C:\path\to\your\attack.pcap

# 使用相对路径
python run_analysis.py ./captures/malware_traffic.pcap
```

### 2. 批量分析当前目录所有PCAP文件

```bash
python run_analysis.py
```

### 3. AI漏洞分析

```bash
# 运行AI分析模块
python api.py

# 这将会：
# 1. 读取提取的网络流量数据
# 2. 发送给AI模型进行漏洞分析
# 3. 生成详细的安全分析报告
```

### 4. 使用主分析器（高级选项）

```bash
# 分析单个文件
python pcap_analyzer.py -f log4jrce.pcap -o log4j_analysis

# 分析整个目录
python pcap_analyzer.py -d <文件路径> -o all_pcaps_analysis

# 只输出CSV格式
python pcap_analyzer.py -f test.pcap --format csv

# 只输出JSON格式
python pcap_analyzer.py -f test.pcap --format json
```

## 输出字段说明

提取的数据包含以下信息：

- **file_name**: PCAP文件名
- **packet_number**: 数据包编号
- **timestamp**: 时间戳
- **protocol**: 协议类型（TCP/UDP）
- **src_ip/dst_ip**: 源/目标IP地址
- **src_port/dst_port**: 源/目标端口
- **method**: HTTP请求方法（GET/POST等）
- **path**: 请求路径
- **host**: 目标主机
- **user_agent**: 用户代理
- **content_type**: 内容类型
- **status_code**: HTTP响应状态码
- **content_length**: 内容长度
- **cookies**: Cookie信息
- **request_headers**: 请求头部（JSON格式）
- **response_headers**: 响应头部（JSON格式）
- **request_body**: 请求体内容
- **response_body**: 响应体内容
- **raw_payload**: 原始payload数据
- **payload_size**: payload大小

## 示例输出

### 1. PCAP分析结果
分析完成后会生成：
- **CSV文件**：结构化的流量数据，适合在Excel中查看
- **JSON文件**：机器可读格式，便于程序化处理
- **控制台摘要**：显示协议分布、HTTP方法统计等

### 2. AI分析报告
AI模型会生成包含以下内容的安全分析报告：
- **漏洞类型识别**：RCE、SQL注入、XSS、反序列化等
- **攻击载荷分析**：恶意代码、利用代码的详细解析
- **威胁等级评估**：高/中/低风险分级
- **修复建议**：针对性的安全加固建议
- **IOC提取**：攻击指标和特征码

### 3. 支持的漏洞类型
基于项目中的PCAP样本，工具能够识别：
- **远程代码执行(RCE)**：Log4j、Spring等框架漏洞
- **反序列化漏洞**：Java、PHP反序列化攻击
- **文件上传漏洞**：任意文件上传和Webshell
- **SQL注入**：各种注入攻击模式
- **权限绕过**：身份认证绕过
- **信息泄露**：敏感信息暴露

## 项目结构

```
POC_feature_extract/
├── api.py                     # AI分析API调用模块
├── pcap_analyzer.py           # 核心PCAP分析器
├── run_analysis.py           # 主运行脚本
├── prompt.py                 # AI提示词配置
├── extract_attacks.py        # 攻击特征提取
├── security_analyzer.py      # 安全分析模块
├── requirements.txt          # 依赖包列表
├── results/                  # AI分析结果目录
├── *.pcap                   # 测试用的攻击流量样本
└── README.md                # 项目说明文档
```

## 注意事项

### 使用须知
1. 确保你有足够的权限读取PCAP文件
2. 大型PCAP文件可能需要较长时间处理
3. **文件路径支持相对路径和绝对路径，会自动转换为绝对路径处理**
4. **分析结果始终保存在当前工作目录，不受输入文件路径影响**

### AI分析相关
5. 需要配置有效的AI API密钥
6. AI分析会产生API调用费用，请合理控制使用
7. 对于敏感数据，建议使用本地部署的AI模型

### 技术限制
8. 工具会自动过滤无关的数据包，只保留有意义的流量信息
9. 对于加密流量（HTTPS），只能提取基本的连接信息和元数据
10. AI分析结果仅供参考，建议结合人工分析进行验证

## 适用场景

### 安全研究
- **漏洞研究和分析**：快速识别新型攻击模式
- **恶意流量检测**：自动化识别恶意网络行为
- **攻击技术分析**：深入理解攻击手法和载荷

### 渗透测试
- **渗透测试后的流量分析**：验证攻击效果和影响范围
- **红蓝对抗演练**：分析攻击流量和防御效果
- **安全评估**：全面评估网络安全状况

### 应急响应
- **安全事件调查**：快速分析攻击流量和影响范围
- **威胁狩猎**：主动发现潜在的安全威胁
- **取证分析**：提供详细的攻击证据和分析报告

### 安全运营
- **Web应用安全监控**：实时监控和分析Web攻击
- **网络流量审计**：定期审计网络安全状况
- **安全培训**：作为安全培训的实战分析工具

## 贡献指南

欢迎贡献代码和改进建议！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 免责声明

本工具仅用于合法的安全研究和测试目的。使用者应当：
- 仅在获得明确授权的环境中使用
- 遵守当地法律法规和道德规范
- 不得用于非法攻击和恶意活动

作者不对工具的误用承担任何责任。
