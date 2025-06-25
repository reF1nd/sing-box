#!/usr/bin/env python3
"""
简单的 GitHub Actions 工作流语法检查脚本
"""

import yaml
import sys
import re

def check_workflow_syntax(file_path):
    """检查工作流语法"""
    print(f"🔍 检查工作流文件: {file_path}")
    print("=" * 50)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 检查常见的语法问题
        issues = []
        
        # 检查 secrets 使用
        secrets_pattern = r'if:\s*.*secrets\.[A-Z_]+.*!='
        if re.search(secrets_pattern, content):
            issues.append("❌ 发现 secrets 条件语法错误 - 应该使用 ${{ secrets.NAME }}")
        
        # 检查环境变量使用
        env_pattern = r'env\.[A-Z_]+.*!='
        if re.search(env_pattern, content):
            issues.append("⚠️ 发现 env 变量条件使用 - 确认是否应该使用 secrets")
        
        # 尝试解析 YAML
        try:
            yaml_data = yaml.safe_load(content)
            print("✅ YAML 语法正确")
        except yaml.YAMLError as e:
            issues.append(f"❌ YAML 语法错误: {str(e)}")
        
        # 检查必需字段
        if yaml_data:
            if 'name' not in yaml_data:
                issues.append("❌ 缺少 'name' 字段")
            
            if 'on' not in yaml_data and True not in yaml_data:
                issues.append("❌ 缺少 'on' 字段")
            
            if 'jobs' not in yaml_data:
                issues.append("❌ 缺少 'jobs' 字段")
            else:
                print(f"✅ 找到 {len(yaml_data['jobs'])} 个 jobs")
                for job_name in yaml_data['jobs'].keys():
                    print(f"  • {job_name}")
        
        # 输出检查结果
        if issues:
            print("\n🚨 发现问题:")
            for issue in issues:
                print(f"  {issue}")
            return False
        else:
            print("\n🎉 工作流语法检查通过！")
            return True
            
    except Exception as e:
        print(f"❌ 文件读取错误: {str(e)}")
        return False

def main():
    """主函数"""
    workflow_file = ".github/workflows/ref1nd-release.yml"
    
    if check_workflow_syntax(workflow_file):
        print("\n✅ 工作流文件准备就绪，可以提交和推送！")
        sys.exit(0)
    else:
        print("\n❌ 请修复上述问题后再提交。")
        sys.exit(1)

if __name__ == "__main__":
    main()
