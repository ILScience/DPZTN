import os
import pandas as pd


def extract_and_rename_behavior_score(input_folder, output_file, list_name):
    # 存储所有提取后的数据
    all_data = []

    # 遍历文件夹中的所有CSV文件
    for filename in os.listdir(input_folder):
        if filename.endswith('.csv'):
            file_path = os.path.join(input_folder, filename)

            # 读取CSV文件
            df = pd.read_csv(file_path, encoding='utf-8')

            # 检查文件中是否有 behavior_score 列
            if list_name in df.columns:
                # 提取 behavior_score 列并重新命名为文件名（去掉扩展名）
                column_name = os.path.splitext(filename)[0]
                df_renamed = df[[list_name]].rename(columns={list_name: column_name})

                # 添加到合并数据的列表中
                all_data.append(df_renamed)

    # 合并所有数据
    if all_data:
        merged_data = pd.concat(all_data, axis=1)

        # 将合并后的数据保存为新的 CSV 文件
        merged_data.to_csv(output_file, encoding='utf-8')
        print(f"Successfully saved the merged data to {output_file}")
    else:
        print("No valid 'behavior_score' columns found in any CSV files.")


# 设置输入文件夹路径和输出文件路径
input_folder = 'D:\\01_08_零信任网元\\数据处理\\多用户访问\\'  # 替换为你存放CSV文件的文件夹路径
output_file = 'D:\\01_08_零信任网元\\数据处理\\CPU.csv'  # 替换为你想保存的输出文件路径
# list_name ='CPU'
# list_name = 'memory_usage_percent'
list_name ='cpu_usage'

# 调用函数处理 CSV 文件
extract_and_rename_behavior_score(input_folder, output_file, list_name)
