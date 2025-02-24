from soft_score import *
import numpy as np
import random
import gc


def simulated_annealing(user_data, gateway, delta_range, sigma_range, n, initial_temp, cooling_rate, max_iter):
    """
    模拟退火算法优化参数

    :param user_data: 用户数据
    :param gateway: 网关数据
    :param delta_range: delta参数范围
    :param sigma_range: sigma参数范围
    :param n: 攻击次数
    :param initial_temp: 初始温度
    :param cooling_rate: 降温速率
    :param max_iter: 最大迭代次数
    :return: 最优delta, 最优sigma, 最优分数
    """
    def random_sample(range_list):
        """随机生成符合范围的一个解"""
        sample = [random.uniform(r[0], r[1]) for r in range_list]
        sample_sum = sum(sample)
        return [x / sample_sum for x in sample]  # 确保和为1

    def calculate_score(user_data, gateway, delta, sigma):
        """计算当前解的分数"""
        user_data_copy = user_data.copy()
        gateway_copy = gateway.copy()

        delta_dict = {"P_AS": delta[0], "P_ACS": delta[1], "P_LAF": delta[2], "f_RL1": delta[3]}
        sigma_dict = {"P_AF": sigma[0], "P_ACF": sigma[1], "P_SAC": sigma[2], "f_RL": sigma[3], "MTP": sigma[4]}

        # 执行攻击或越权访问
        _, _, score_diff = user_access(user_data_copy, gateway_copy, delta_dict, sigma_dict, n)

        del user_data_copy, gateway_copy
        gc.collect()

        return score_diff

    # 初始化解
    current_delta = [0.05, 0.85, 0.05, 0.05]  # 初始delta
    current_sigma = [0.05, 0.05, 0.05, 0.05, 0.8]  # 初始sigma
    current_score = calculate_score(user_data, gateway, current_delta, current_sigma)

    best_delta = current_delta
    best_sigma = current_sigma
    best_score = current_score

    temp = initial_temp

    for iteration in range(max_iter):
        # 随机生成新解
        new_delta = random_sample(delta_range)
        new_sigma = random_sample(sigma_range)
        print(new_delta)
        print(new_sigma)
        new_score = calculate_score(user_data, gateway, new_delta, new_sigma)

        # 接受新解的概率
        if new_score < current_score or random.random() < np.exp((current_score - new_score) / temp):
            current_delta, current_sigma, current_score = new_delta, new_sigma, new_score

        # 更新最优解
        if current_score < best_score:
            best_delta, best_sigma, best_score = current_delta, current_sigma, current_score

        # 降温
        temp *= cooling_rate

        print(f"Iteration {iteration+1}: Best Score = {best_score}, Temperature = {temp}")
    # 将最终的delta和sigma限制为三位小数
    best_delta = [round(x, 3) for x in best_delta]
    best_sigma = [round(x, 3) for x in best_sigma]

    return best_delta, best_sigma, best_score


# 初始用户值
ac, asf = 1, 1
acc, acsf = 1, 1
auth_end_time = 0
acc_time = 1
lac = 1
capl = 15
carl = random.randint(0, capl - 5)
mtp = 0
hbhs = 1
hbhr = 0
user_data = {"AC": ac, "ASF": asf, "FAF": (ac - asf), "AUTH_TS": auth_end_time, "ACC": acc, "ACSF": acsf,
             "FACF": (acc - acsf), "AS_TS": acc_time, "CAPL": capl, "CARL": carl,
             "LAC": lac, "ACF": acc / (acc_time - auth_end_time), "SACF": acsf / (acc_time - auth_end_time),
             "MTP": mtp, "HBHS": hbhs, "HBHR": hbhr, "behavior_score": 1}
gasf = 1
gac = 1
gacsf = 1
gacc = 1
grv = 1
grr = 0

gateway = {"GASF": gasf, "GAC": gac, "GACSF": gacsf, "GACC": gacc, "User_Num": 1, "GRV": grv, "GRR": grr}

# 定义delta和sigma的搜索范围
delta_range = [(0, 0.1), (0.8, 0.9), (0, 0.1), (0, 0.1)]
sigma_range = [(0, 0.1), (0, 0.1), (0, 0.1), (0, 0.1), (0.75, 0.85)]

# 模拟退火搜索
initial_temp = 10
cooling_rate = 0.95
max_iter = 100

best_delta, best_sigma, best_score = simulated_annealing(user_data, gateway, delta_range, sigma_range, 3, initial_temp, cooling_rate, max_iter)

print(f"Best Delta: {best_delta}")
print(f"Best Sigma: {best_sigma}")
print(f"Best Score: {best_score:.3f}")
