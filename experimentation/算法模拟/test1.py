import pandas as pd

# 假设csv文件的路径为 '/mnt/data/result.csv'
file_path = '网格搜索.csv'

# 读取csv文件为DataFrame
df = pd.read_csv(file_path)

# 修改重复列名
df.columns = [f'{col}_{i + 1}' if list(df.columns).count(col) > 1 else col
              for i, col in enumerate(df.columns)]

# 定义x的列名，除去最后一列
x_columns = df.columns.tolist()[-11:-1]
print(x_columns)

# 确保'Difference in behavior score scores'列存在
y_column = 'score_diff'

# 创建空的DataFrame，用于存储结果
dataframe_new = pd.DataFrame()

# 对每个x_column进行groupby操作
for i in range(0, len(x_columns)):
    # 对每个x_column进行分组并求'min'值
    data = df.groupby(x_columns[i], as_index=False)[y_column].min()
    print(data)
    dataframe_new = pd.concat([dataframe_new, data],axis=1)

# 保存新的DataFrame为csv文件
output_file_path = '网格_minimized.csv'
dataframe_new.to_csv(output_file_path, index=False)
