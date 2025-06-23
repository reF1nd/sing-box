#!/usr/bin/env python3
"""
GitHub Actions 工作流语法验证脚本
用于验证 reF1nd 工作流文件的语法正确性
"""

import yaml
import sys
import os

def validate_yaml_file(file_path):
    """验证 YAML 文件语法"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 尝试解析 YAML
        yaml_data = yaml.safe_load(content)

        print(f"✅ {file_path} - YAML 语法正确")
        print(f"   解析到的顶级键: {list(yaml_data.keys()) if yaml_data else 'None'}")
        return True, yaml_data

    except yaml.YAMLError as e:
        print(f"❌ {file_path} - YAML 语法错误:")
        print(f"   {str(e)}")
        return False, None
    except Exception as e:
        print(f"❌ {file_path} - 文件读取错误:")
        print(f"   {str(e)}")
        return False, None

def validate_github_workflow(yaml_data, file_path):
    """验证 GitHub Actions 工作流结构"""
    errors = []
    warnings = []
    
    # 检查必需字段
    if 'name' not in yaml_data:
        errors.append("缺少 'name' 字段")

    # 检查 'on' 字段 (可能被解析为 True)
    if 'on' not in yaml_data and True not in yaml_data:
        errors.append("缺少 'on' 字段")

    if 'jobs' not in yaml_data:
        errors.append("缺少 'jobs' 字段")
    
    # 检查 jobs 结构
    if 'jobs' in yaml_data:
        jobs = yaml_data['jobs']
        if not isinstance(jobs, dict):
            errors.append("'jobs' 必须是字典类型")
        else:
            for job_name, job_config in jobs.items():
                if 'runs-on' not in job_config:
                    errors.append(f"Job '{job_name}' 缺少 'runs-on' 字段")
                
                if 'steps' not in job_config:
                    errors.append(f"Job '{job_name}' 缺少 'steps' 字段")
                elif not isinstance(job_config['steps'], list):
                    errors.append(f"Job '{job_name}' 的 'steps' 必须是列表类型")
    
    # 检查触发条件 (处理 'on' 被解析为 True 的情况)
    on_config = yaml_data.get('on') or yaml_data.get(True)
    if on_config:
        if isinstance(on_config, dict):
            if 'push' in on_config and 'tags' in on_config['push']:
                tags = on_config['push']['tags']
                if isinstance(tags, list) and '*reF1nd*' in tags:
                    print("✅ 找到 reF1nd 标签触发条件")

            if 'workflow_dispatch' in on_config:
                print("✅ 支持手动触发")
    
    return errors, warnings

def main():
    """主函数"""
    print("🔍 验证 reF1nd 工作流语法...")
    print("=" * 40)
    
    workflow_files = [
        '.github/workflows/ref1nd-release.yml',
        '.github/workflows/ref1nd-test.yml'
    ]
    
    total_files = 0
    valid_files = 0
    
    for file_path in workflow_files:
        if not os.path.exists(file_path):
            print(f"⚠️ {file_path} - 文件不存在，跳过")
            continue
        
        total_files += 1
        print(f"\n📄 验证文件: {file_path}")
        print("-" * 30)
        
        # 验证 YAML 语法
        is_valid, yaml_data = validate_yaml_file(file_path)
        
        if is_valid:
            valid_files += 1
            
            # 验证 GitHub Actions 工作流结构
            errors, warnings = validate_github_workflow(yaml_data, file_path)
            
            if errors:
                print("❌ 工作流结构错误:")
                for error in errors:
                    print(f"   • {error}")
                valid_files -= 1
            else:
                print("✅ 工作流结构正确")
            
            if warnings:
                print("⚠️ 工作流警告:")
                for warning in warnings:
                    print(f"   • {warning}")
    
    print("\n" + "=" * 40)
    print(f"📊 验证结果: {valid_files}/{total_files} 文件通过验证")
    
    if valid_files == total_files and total_files > 0:
        print("🎉 所有工作流文件语法正确！")
        return 0
    else:
        print("❌ 存在语法错误，请修复后重试")
        return 1

if __name__ == "__main__":
    sys.exit(main())
