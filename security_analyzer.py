#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全漏洞PCAP分析器
专门用于分析安全漏洞相关的网络流量
"""

import os
import json
import re
from pcap_analyzer import PCAPAnalyzer
from datetime import datetime

class SecurityAnalyzer(PCAPAnalyzer):
    def __init__(self):
        super().__init__()
        self.vulnerability_patterns = {
            'sql_injection': [
                r'union\s+select', r'order\s+by', r'information_schema',
                r'@@version', r'waitfor\s+delay', r'sleep\(\d+\)'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'onload\s*=',
                r'onerror\s*=', r'alert\s*\(', r'document\.cookie'
            ],
            'rce': [
                r'system\s*\(', r'exec\s*\(', r'eval\s*\(',
                r'cmd\s*=', r'command\s*=', r'\|.*whoami'
            ],
            'directory_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e\\'
            ],
            'deserialization': [
                r'java\.lang\.Runtime', r'ProcessBuilder',
                r'rO0AB', r'aced0005', r'serialVersionUID'
            ],
            'file_upload': [
                r'filename\s*=.*\.php', r'filename\s*=.*\.jsp',
                r'filename\s*=.*\.asp', r'Content-Type:\s*multipart'
            ]
        }
        
        self.security_findings = []
    
    def analyze_security_patterns(self, data):
        """分析安全模式"""
        findings = []
        
        # 组合所有可搜索的文本
        search_text = " ".join([
            data.get('path', ''),
            data.get('request_body', ''),
            data.get('response_body', ''),
            data.get('raw_payload', ''),
            data.get('request_headers', ''),
            data.get('user_agent', '')
        ]).lower()
        
        # 检查每种漏洞模式
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, search_text, re.IGNORECASE):
                    finding = {
                        'vulnerability_type': vuln_type,
                        'pattern_matched': pattern,
                        'file_name': data.get('file_name', ''),
                        'packet_number': data.get('packet_number', ''),
                        'timestamp': data.get('timestamp', ''),
                        'src_ip': data.get('src_ip', ''),
                        'dst_ip': data.get('dst_ip', ''),
                        'method': data.get('method', ''),
                        'path': data.get('path', ''),
                        'payload_snippet': search_text[:200] + '...' if len(search_text) > 200 else search_text
                    }
                    findings.append(finding)
                    break  # 每种类型只记录一次
        
        return findings
    
    def analyze_pcap(self, pcap_file):
        """覆盖父类方法，添加安全分析"""
        # 调用父类方法进行基础分析
        result = super().analyze_pcap(pcap_file)
        
        # 对每条记录进行安全分析
        for data in self.extracted_data:
            security_findings = self.analyze_security_patterns(data)
            self.security_findings.extend(security_findings)
        
        return result
    
    def generate_security_report(self, output_file):
        """生成安全分析报告"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_packets_analyzed': len(self.extracted_data),
            'security_findings_count': len(self.security_findings),
            'vulnerability_summary': {},
            'findings': self.security_findings
        }
        
        # 统计漏洞类型
        for finding in self.security_findings:
            vuln_type = finding['vulnerability_type']
            if vuln_type not in report['vulnerability_summary']:
                report['vulnerability_summary'][vuln_type] = 0
            report['vulnerability_summary'][vuln_type] += 1
        
        # 保存报告
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        return report
    
    def print_security_summary(self):
        """打印安全分析摘要"""
        print(f"\n=== 安全分析摘要 ===")
        print(f"总分析数据包数: {len(self.extracted_data)}")
        print(f"发现安全问题数: {len(self.security_findings)}")
        
        if self.security_findings:
            vuln_counts = {}
            for finding in self.security_findings:
                vuln_type = finding['vulnerability_type']
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
            
            print("\n漏洞类型分布:")
            for vuln_type, count in sorted(vuln_counts.items()):
                print(f"  - {vuln_type}: {count}")
            
            print(f"\n前5个安全发现:")
            for i, finding in enumerate(self.security_findings[:5], 1):
                print(f"{i}. {finding['vulnerability_type']} - {finding['file_name']} (包#{finding['packet_number']})")
                print(f"   模式: {finding['pattern_matched']}")
                print(f"   路径: {finding['path']}")
        else:
            print("未发现明显的安全问题")

def main():
    """主函数"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_files = [f for f in os.listdir(current_dir) if f.endswith('.pcap')]
    
    if not pcap_files:
        print("当前目录没有找到PCAP文件")
        return
    
    print(f"找到 {len(pcap_files)} 个PCAP文件，开始安全分析...")
    
    analyzer = SecurityAnalyzer()
    
    # 分析所有文件
    for pcap_file in pcap_files:
        print(f"分析文件: {pcap_file}")
        try:
            analyzer.analyze_pcap(pcap_file)
        except Exception as e:
            print(f"分析 {pcap_file} 时出错: {e}")
    
    # 生成报告
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 基础分析结果
    analyzer.save_to_csv(f"pcap_analysis_{timestamp}.csv")
    analyzer.save_to_json(f"pcap_analysis_{timestamp}.json")
    
    # 安全分析报告
    security_report = analyzer.generate_security_report(f"security_analysis_{timestamp}.json")
    
    # 打印摘要
    analyzer.print_summary()
    analyzer.print_security_summary()
    
    print(f"\n文件已生成:")
    print(f"- pcap_analysis_{timestamp}.csv (完整分析结果)")
    print(f"- pcap_analysis_{timestamp}.json (完整分析结果)")
    print(f"- security_analysis_{timestamp}.json (安全分析报告)")

if __name__ == "__main__":
    main()
