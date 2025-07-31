#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP流量分析器
用于提取PCAP文件中的HTTP/HTTPS请求、响应、payload等关键信息
"""

import os
import json
import csv
from datetime import datetime
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import argparse
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PCAPAnalyzer:
    def __init__(self):
        self.flows = {}
        self.extracted_data = []
        
    def analyze_pcap(self, pcap_file):
        """分析单个PCAP文件"""
        logger.info(f"开始分析文件: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            logger.info(f"成功读取 {len(packets)} 个数据包")
            
            for i, packet in enumerate(packets):
                self._process_packet(packet, i, pcap_file)
                
        except Exception as e:
            logger.error(f"分析文件 {pcap_file} 时出错: {str(e)}")
            
        return self.extracted_data
    
    def _process_packet(self, packet, packet_num, pcap_file):
        """处理单个数据包"""
        try:
            # 基本包信息
            packet_info = {
                'file_name': os.path.basename(pcap_file),
                'packet_number': packet_num,
                'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                'protocol': '',
                'src_ip': '',
                'dst_ip': '',
                'src_port': '',
                'dst_port': '',
                'method': '',
                'path': '',
                'host': '',
                'user_agent': '',
                'content_type': '',
                'request_headers': '',
                'response_headers': '',
                'request_body': '',
                'response_body': '',
                'status_code': '',
                'content_length': '',
                'cookies': '',
                'payload_size': len(packet)
            }
            
            # 提取IP层信息
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
            # 提取传输层信息
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['protocol'] = 'TCP'
            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['protocol'] = 'UDP'
            
            # 处理HTTP请求
            if HTTPRequest in packet:
                self._extract_http_request(packet, packet_info)
                
            # 处理HTTP响应
            if HTTPResponse in packet:
                self._extract_http_response(packet, packet_info)
                
            # 提取原始payload
            if Raw in packet:
                raw_data = packet[Raw].load
                packet_info['raw_payload'] = self._safe_decode(raw_data)
            else:
                packet_info['raw_payload'] = ''
                
            # 只保存有意义的数据包（有HTTP信息或payload）
            if (packet_info['method'] or packet_info['status_code'] or 
                packet_info.get('raw_payload', '') or packet_info['request_body'] or 
                packet_info['response_body']):
                self.extracted_data.append(packet_info)
                
        except Exception as e:
            logger.warning(f"处理数据包 {packet_num} 时出错: {str(e)}")
    
    def _extract_http_request(self, packet, packet_info):
        """提取HTTP请求信息"""
        try:
            http_layer = packet[HTTPRequest]
            
            # 基本请求信息
            packet_info['method'] = http_layer.Method.decode('utf-8', errors='ignore')
            packet_info['path'] = http_layer.Path.decode('utf-8', errors='ignore')
            
            # 提取请求头
            headers = {}
            if http_layer.fields:
                for field, value in http_layer.fields.items():
                    if field not in ['Method', 'Path', 'Http_Version']:
                        headers[field] = self._safe_decode(value)
            
            packet_info['request_headers'] = json.dumps(headers, ensure_ascii=False)
            packet_info['host'] = headers.get('Host', '')
            packet_info['user_agent'] = headers.get('User-Agent', '')
            packet_info['content_type'] = headers.get('Content-Type', '')
            packet_info['cookies'] = headers.get('Cookie', '')
            
            # 提取请求体
            if Raw in packet:
                packet_info['request_body'] = self._safe_decode(packet[Raw].load)
                
        except Exception as e:
            logger.warning(f"提取HTTP请求信息时出错: {str(e)}")
    
    def _extract_http_response(self, packet, packet_info):
        """提取HTTP响应信息"""
        try:
            http_layer = packet[HTTPResponse]
            
            # 响应状态码
            packet_info['status_code'] = http_layer.Status_Code.decode('utf-8', errors='ignore')
            
            # 提取响应头
            headers = {}
            if http_layer.fields:
                for field, value in http_layer.fields.items():
                    if field not in ['Http_Version', 'Status_Code', 'Reason_Phrase']:
                        headers[field] = self._safe_decode(value)
            
            packet_info['response_headers'] = json.dumps(headers, ensure_ascii=False)
            packet_info['content_length'] = headers.get('Content-Length', '')
            
            # 提取响应体
            if Raw in packet:
                packet_info['response_body'] = self._safe_decode(packet[Raw].load)
                
        except Exception as e:
            logger.warning(f"提取HTTP响应信息时出错: {str(e)}")
    
    def _safe_decode(self, data):
        """安全解码字节数据"""
        if isinstance(data, bytes):
            try:
                # 先尝试UTF-8解码
                decoded = data.decode('utf-8', errors='ignore')
                # 清理可能导致CSV问题的特殊字符
                return self._sanitize_for_csv(decoded)
            except:
                return self._sanitize_for_csv(str(data))
        return self._sanitize_for_csv(str(data))
    
    def _sanitize_for_csv(self, text):
        """清理文本中可能导致CSV问题的字符"""
        if not isinstance(text, str):
            text = str(text)
        
        # 替换或移除可能导致CSV问题的字符
        text = text.replace('\x00', '')  # 移除空字符
        text = text.replace('\r\n', '\\n')  # 替换换行符
        text = text.replace('\n', '\\n')
        text = text.replace('\r', '\\r')
        text = text.replace('\t', '\\t')
        text = text.replace('"', '\\"')  # 转义双引号
        
        # 限制长度以避免过大的字段
        if len(text) > 5000:
            text = text[:5000] + "...[truncated]"
        
        return text
    
    def save_to_csv(self, output_file):
        """保存结果到CSV文件"""
        if not self.extracted_data:
            logger.warning("没有数据需要保存")
            return
            
        fieldnames = [
            'file_name', 'packet_number', 'timestamp', 'protocol',
            'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'method', 'path', 'host', 'user_agent', 'content_type',
            'status_code', 'content_length', 'cookies',
            'request_headers', 'response_headers',
            'request_body', 'response_body', 'raw_payload', 'payload_size'
        ]
        
        # 清理数据，确保所有字段都存在
        cleaned_data = []
        for row in self.extracted_data:
            cleaned_row = {}
            for field in fieldnames:
                value = row.get(field, '')
                if isinstance(value, (list, dict)):
                    value = json.dumps(value, ensure_ascii=False)
                cleaned_row[field] = self._sanitize_for_csv(str(value))
            cleaned_data.append(cleaned_row)
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(
                    csvfile, 
                    fieldnames=fieldnames,
                    quoting=csv.QUOTE_ALL,  # 对所有字段加引号
                    escapechar='\\'  # 设置转义字符
                )
                writer.writeheader()
                writer.writerows(cleaned_data)
            
            logger.info(f"结果已保存到: {output_file}")
        except Exception as e:
            logger.error(f"保存CSV文件时出错: {str(e)}")
            # 尝试备用方法
            self._save_csv_fallback(output_file, cleaned_data, fieldnames)
    
    def _save_csv_fallback(self, output_file, data, fieldnames):
        """备用CSV保存方法"""
        try:
            logger.info("尝试使用备用方法保存CSV...")
            with open(output_file, 'w', encoding='utf-8') as f:
                # 写入表头
                f.write(','.join(f'"{field}"' for field in fieldnames) + '\n')
                
                # 写入数据
                for row in data:
                    values = []
                    for field in fieldnames:
                        value = str(row.get(field, ''))
                        # 简单的引号转义
                        value = value.replace('"', '""')
                        values.append(f'"{value}"')
                    f.write(','.join(values) + '\n')
            
            logger.info(f"使用备用方法成功保存到: {output_file}")
        except Exception as e:
            logger.error(f"备用保存方法也失败: {str(e)}")
            # 最后的保险方法：保存为文本文件
            txt_file = output_file.replace('.csv', '.txt')
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write("PCAP分析结果\n")
                f.write("=" * 50 + "\n\n")
                for i, row in enumerate(data):
                    f.write(f"记录 {i+1}:\n")
                    for field in fieldnames:
                        f.write(f"  {field}: {row.get(field, '')}\n")
                    f.write("\n")
            logger.info(f"已保存为文本格式: {txt_file}")
    
    def save_to_json(self, output_file):
        """保存结果到JSON文件"""
        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.extracted_data, jsonfile, ensure_ascii=False, indent=2)
        
        logger.info(f"结果已保存到: {output_file}")
    
    def print_summary(self):
        """打印分析摘要"""
        if not self.extracted_data:
            print("没有提取到任何数据")
            return
            
        print(f"\n=== 分析摘要 ===")
        print(f"总共提取的数据包数量: {len(self.extracted_data)}")
        
        # 统计各种协议
        protocols = {}
        methods = {}
        status_codes = {}
        
        for data in self.extracted_data:
            protocol = data.get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
            
            if data.get('method'):
                method = data['method']
                methods[method] = methods.get(method, 0) + 1
                
            if data.get('status_code'):
                status = data['status_code']
                status_codes[status] = status_codes.get(status, 0) + 1
        
        print(f"协议分布: {protocols}")
        print(f"HTTP方法分布: {methods}")
        print(f"响应状态码分布: {status_codes}")

def main():
    parser = argparse.ArgumentParser(description='PCAP流量分析器')
    parser.add_argument('-f', '--file', help='单个PCAP文件路径')
    parser.add_argument('-d', '--directory', help='PCAP文件目录路径')
    parser.add_argument('-o', '--output', default='pcap_analysis', help='输出文件前缀')
    parser.add_argument('--format', choices=['csv', 'json', 'both'], default='both', help='输出格式')
    
    args = parser.parse_args()
    
    analyzer = PCAPAnalyzer()
    
    if args.file:
        # 分析单个文件
        analyzer.analyze_pcap(args.file)
    elif args.directory:
        # 分析目录中的所有PCAP文件
        pcap_files = [f for f in os.listdir(args.directory) if f.endswith('.pcap')]
        logger.info(f"找到 {len(pcap_files)} 个PCAP文件")
        
        for pcap_file in pcap_files:
            file_path = os.path.join(args.directory, pcap_file)
            analyzer.analyze_pcap(file_path)
    else:
        print("请指定要分析的文件或目录")
        return
    
    # 保存结果
    if args.format in ['csv', 'both']:
        analyzer.save_to_csv(f"{args.output}.csv")
    
    if args.format in ['json', 'both']:
        analyzer.save_to_json(f"{args.output}.json")
    
    # 打印摘要
    analyzer.print_summary()

if __name__ == "__main__":
    main()
