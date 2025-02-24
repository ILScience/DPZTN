import os
import pandas as pd

def extract_and_rename_behavior_score(input_folder, output_file):
    # 存储所有提取后的数据
    capl_data = []
    carl_data = []

    # 遍历文件夹中的所有CSV文件
    for filename in os.listdir(input_folder):
        if filename.endswith('.csv'):
            file_path = os.path.join(input_folder, filename)

            # 读取CSV文件
            df = pd.read_csv(file_path, encoding='utf-8')
            column_name = os.path.splitext(filename)[0]


            # 假设文件名决定了是CAPL列还是CARL列
            if 'CAPL' in df.columns:  # 根据文件名判断是否为CAPL
                df_renamed = df[['CAPL']].rename(columns={'CAPL': column_name})
                capl_data.append(df_renamed)
            elif 'CARL' in df.columns:  # 根据文件名判断是否为CARL
                df_renamed = df[['CARL']].rename(columns={'CARL': column_name})
                carl_data.append(df_renamed)

    # 合并所有数据
    if capl_data or carl_data:
        # 合并 CAPL 和 CARL 数据
        merged_data = pd.concat(capl_data + carl_data, axis=1)

        # 将合并后的数据保存为新的 CSV 文件
        merged_data.to_csv(output_file, encoding='utf-8', index=False)
        print(f"Successfully saved the merged data to {output_file}")
    else:
        print("No valid 'behavior_score' columns found in any CSV files.")

# 设置输入文件夹路径和输出文件路径
input_folder = 'D:\\01_08_零信任网元\\数据处理\\'  # 替换为你存放CSV文件的文件夹路径
output_file = 'D:\\01_08_零信任网元\\数据处理\\用户等级.csv'  # 替换为你想保存的输出文件路径

# 调用函数处理 CSV 文件
extract_and_rename_behavior_score(input_folder, output_file)
