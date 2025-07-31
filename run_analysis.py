#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单的PCAP分析示例脚本
"""

import os
import sys
from pcap_analyzer import PCAPAnalyzer

def analyze_all_pcaps():
    """分析当前目录下的所有PCAP文件"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_files = [f for f in os.listdir(current_dir) if f.endswith('.pcap')]
    
    if not pcap_files:
        print("当前目录没有找到PCAP文件")
        return
    
    print(f"找到 {len(pcap_files)} 个PCAP文件:")
    for i, file in enumerate(pcap_files, 1):
        print(f"{i}. {file}")
    
    analyzer = PCAPAnalyzer()
    
    # 分析所有文件
    for pcap_file in pcap_files:
        print(f"\n正在分析: {pcap_file}")
        try:
            analyzer.analyze_pcap(pcap_file)
        except Exception as e:
            print(f"分析 {pcap_file} 时出错: {e}")
            import traceback
            traceback.print_exc()
            continue  # 继续分析下一个文件
    
    # 保存结果
    if analyzer.extracted_data:
        timestamp = str(int(time.time()))
        csv_file = f"pcap_analysis_{timestamp}.csv"
        json_file = f"pcap_analysis_{timestamp}.json"
        
        try:
            analyzer.save_to_csv(csv_file)
            analyzer.save_to_json(json_file)
            analyzer.print_summary()
            
            print(f"\n分析完成！结果已保存到:")
            print(f"- {csv_file}")
            print(f"- {json_file}")
        except Exception as e:
            print(f"保存结果时出错: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("\n没有提取到任何有效数据")

def analyze_single_pcap(filepath):
    """分析单个PCAP文件"""
    # 支持相对路径和绝对路径
    if not os.path.isabs(filepath):
        # 如果是相对路径，基于当前工作目录
        filepath = os.path.abspath(filepath)
    
    if not os.path.exists(filepath):
        print(f"文件不存在: {filepath}")
        return
    
    print(f"正在分析文件: {filepath}")
    analyzer = PCAPAnalyzer()
    
    try:
        analyzer.analyze_pcap(filepath)
        
        if analyzer.extracted_data:
            # 使用文件名作为输出前缀，保存在当前目录
            filename = os.path.basename(filepath)
            base_name = os.path.splitext(filename)[0]
            csv_file = f"{base_name}_analysis.csv"
            json_file = f"{base_name}_analysis.json"
            
            analyzer.save_to_csv(csv_file)
            analyzer.save_to_json(json_file)
            analyzer.print_summary()
            
            print(f"\n分析完成！结果已保存到:")
            print(f"- {csv_file}")
            print(f"- {json_file}")
        else:
            print(f"\n文件 {filepath} 中没有提取到任何有效数据")
            
    except Exception as e:
        print(f"分析文件 {filepath} 时出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    import time
    
    if len(sys.argv) > 1:
        # 分析指定的文件路径
        file_path = sys.argv[1]
        print(f"使用命令行参数指定的文件路径: {file_path}")
        analyze_single_pcap(file_path)
    else:
        # 没有参数时分析当前目录的所有文件
        print("未指定文件路径，将分析当前目录下的所有PCAP文件")
        print("用法: python run_analysis.py <pcap文件路径>")
        print("示例: python run_analysis.py C:\\path\\to\\file.pcap")
        print("示例: python run_analysis.py ./file.pcap")
        print("\n继续分析当前目录...\n")
        analyze_all_pcaps()
