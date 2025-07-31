import os
from openai import OpenAI
from prompt import sysprompt, userPromptList
import json


# 创建results文件夹，如果不存在的话
os.makedirs("results", exist_ok=True)

client = OpenAI(
    # 若没有配置环境变量，请用百炼API Key将下行替换为：api_key="sk-xxx",
    api_key="",
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)
for i,userPrompt in enumerate(userPromptList):
    if i!=39 and i!=62:
        continue
    completion = client.chat.completions.create(
        # 模型列表：https://help.aliyun.com/zh/model-studio/getting-started/models
        model="qwen-max",
        messages=[
            {"role": "system", "content": sysprompt},
            {"role": "user", "content": json.dumps(userPrompt, ensure_ascii=False, indent=2)},
        ],
        # Qwen3模型通过enable_thinking参数控制思考过程（开源版默认True，商业版默认False）
        # 使用Qwen3开源版模型时，若未启用流式输出，请将下行取消注释，否则会报错
        extra_body={"enable_thinking": False},
    )
    print(completion.model_dump_json())
    with open(f"results/result-{i}.json","w",encoding="utf-8") as f:
        result = completion.model_dump()
        result["file_name"] = userPrompt["file_name"]
        result["packet_number"] = userPrompt["packet_number"]
        result["attack_payload"] = userPrompt["raw_payload"]
        json.dump(result,f,ensure_ascii=False,indent=4)