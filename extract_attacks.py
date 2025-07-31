import json
import yaml
import os
from pathlib import Path

def extract_attacks_to_yaml():
    """
    提取results文件夹中所有攻击信息并生成YAML文件
    """
    results_dir = Path("results")
    attacks = []
    
    if not results_dir.exists():
        print("results文件夹不存在")
        return
    
    # 遍历results文件夹中的所有JSON文件
    for json_file in results_dir.glob("*.json"):
        print(f"处理文件: {json_file}")
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 提取基本信息
            file_name = data.get("file_name", "未知")
            packet_number = data.get("packet_number", "未知")
            attack_payload = data.get("attack_payload","未知")
            
            
            
            # 解析content中的JSON
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            if content:
                try:
                    # 解析content中的JSON字符串
                    content_data = json.loads(content)
                    
                    # 处理每个攻击项
                    for item in content_data:
                        is_attack = item.get("is_attack", False)
                        
                        # 只处理攻击数据
                        if is_attack:
                            attack_info = {
                                "file_name": file_name,
                                "packet_number": packet_number,
                                "attack_type": item.get("attack_type", "未识别"),
                                "path_interface": item.get("path_interface", "未识别"),
                                "attack_payload": attack_payload,
                                "attack_chain": item.get("attack_chain", "未识别")
                            }
                            attacks.append(attack_info)
                            print(f"  ✓ 发现攻击: {attack_info['attack_type']}")
                        else:
                            print(f"  - 跳过非攻击数据")
                            
                except json.JSONDecodeError as e:
                    print(f"  ✗ 解析content JSON失败: {e}")
               
        except Exception as e:
            print(f"  ✗ 处理文件失败: {e}")
    
    # 生成YAML文件
    if attacks:
        yaml_data = {
            "attacks": attacks,
            "total_count": len(attacks),
            "summary": {
                "total_attacks": len(attacks),
                "attack_types": list(set(attack["attack_type"] for attack in attacks))
            }
        }
        
        output_file = "attacks_summary.yaml"
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(yaml_data, f, allow_unicode=True, indent=2, sort_keys=False)
        
        print(f"\n✓ 成功生成YAML文件: {output_file}")
        print(f"✓ 总共提取到 {len(attacks)} 个攻击记录")
        print(f"✓ 攻击类型: {', '.join(yaml_data['summary']['attack_types'])}")
    else:
        print("\n! 未找到任何攻击记录")

if __name__ == "__main__":
    extract_attacks_to_yaml()
