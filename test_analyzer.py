#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试PCAP分析器
"""

import os
from pcap_analyzer import PCAPAnalyzer

def test_analyzer():
    """测试分析器功能"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_files = [f for f in os.listdir(current_dir) if f.endswith('.pcap')]
    
    if not pcap_files:
        print("没有找到PCAP文件进行测试")
        return
    
    # 选择第一个文件进行测试
    test_file = pcap_files[0]
    print(f"测试文件: {test_file}")
    
    analyzer = PCAPAnalyzer()
    
    try:
        analyzer.analyze_pcap(test_file)
        print(f"成功分析文件，提取到 {len(analyzer.extracted_data)} 条记录")
        
        # 显示前几条记录的摘要
        for i, data in enumerate(analyzer.extracted_data[:3]):
            print(f"\n记录 {i+1}:")
            print(f"  - 协议: {data.get('protocol', 'N/A')}")
            print(f"  - 源IP: {data.get('src_ip', 'N/A')}")
            print(f"  - 目标IP: {data.get('dst_ip', 'N/A')}")
            print(f"  - HTTP方法: {data.get('method', 'N/A')}")
            print(f"  - 路径: {data.get('path', 'N/A')}")
            print(f"  - 状态码: {data.get('status_code', 'N/A')}")
        
        # 保存测试结果
        analyzer.save_to_csv("test_result.csv")
        analyzer.save_to_json("test_result.json")
        analyzer.print_summary()
        
    except Exception as e:
        print(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_analyzer()
