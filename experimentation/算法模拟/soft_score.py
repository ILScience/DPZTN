import math
import os
import time
import random
import csv
import itertools


# 计算用户信誉值
def calculate_reputation(user, gateway, delta):
    # 计算各概率，确保除法结果是浮点数
    if user["AC"] >= 0 and gateway["GAC"] >= 0:
        P_AS = (float(user["ASF"]) / float(user["AC"])) * (float(gateway["GASF"]) / float(gateway["GAC"]))
    else:
        raise ValueError("Invalid values for AC or GAC")

    if user["ACC"] >= 0 and gateway["GACC"] >= 0:
        P_ACS = (float(user["ACSF"]) / float(user["ACC"])) * (float(gateway["GACSF"]) / float(gateway["GACC"]))
        P_LAF = float(user["LAC"]) / float(user["ACC"])
    else:
        raise ValueError("Invalid values for ACC or GACC")

    if user["CARL"] <= user["CAPL"]:
        f_RL = 1
    elif user["CAPL"] > 0:
        f_RL = max(float(user["CAPL"]) / (float(user["CARL"]) - float(user["CAPL"])), 2)
    else:
        f_RL = 1

    # 判断 ACC-ACSF 是否超过阈值 n，调整信誉值
    reputation_penalty = 3 if (
            (user["ACC"] - user["ACSF"]) > 1
            or (user["SACF"] / user["ACF"] > 0.05)
            or user["MTP"] > 0.1
    ) else 1

    # 联合概率
    P_X_given_theta_plus = (
            P_AS * delta["P_AS"] + P_ACS * delta["P_ACS"] + P_LAF * delta["P_LAF"] + f_RL * delta["f_RL1"]
    )

    # 先验概率
    P_X = (
            (float(gateway["GASF"]) / float(gateway["GAC"]))
            * (float(gateway["GACSF"]) / float(gateway["GACC"]))
            * f_RL
    )
    P_theta_plus = gateway["GRV"] if user["HBHS"] == 0 else user["HBHS"]

    # 信誉值
    R_U_plus = (P_X_given_theta_plus * P_theta_plus) / (P_X * reputation_penalty)
    R_U_plus = 1 / (1 + math.exp(-R_U_plus))

    return R_U_plus


# 计算用户风险值
def calculate_risk(user, gateway, sigma):
    # 计算各概率，确保除法结果是浮点数
    P_AF = (1 - float(user["ASF"]) / float(user["AC"])) if user["AC"] > 0 else 0
    P_ACF = (1 - float(user["ACSF"]) / float(user["ACC"])) if user["ACC"] > 0 else 0

    if user["CARL"] <= user["CAPL"]:
        f_RL = 1
    elif user["CAPL"] > 0:
        f_RL = max(float(user["CAPL"]) / (float(user["CARL"]) - float(user["CAPL"])), 2)
    else:
        f_RL = 1

    P_SAC = user["SACF"] / user["ACF"] if user["ACF"] > 0 else 0

    # 判断 ASF-ACSF 和 ACC-ACSF 是否超过阈值 n，调整风险值
    risk_boost = 0.5 if (
            (user["ACC"] - user["ACSF"]) > 1
            or P_SAC > 0.05
            or user["MTP"] > 0.1
    ) else 1

    # 联合概率
    P_X_given_theta_minus = (
            sigma["P_AF"] * P_AF
            + sigma["P_ACF"] * P_ACF
            + sigma["f_RL2"] * f_RL
            + sigma["P_SAC"] * P_SAC
            + sigma["MTP_index"] * user["MTP"]
    )

    # 先验概率
    P_X = (
            (float(gateway["GASF"]) / float(gateway["GAC"]))
            * (float(gateway["GACSF"]) / float(gateway["GACC"]))
            * f_RL
    )
    P_theta_minus = gateway["GRR"] if user["HBHR"] == 0 else user["HBHR"]

    # 风险值
    R_U_minus = (P_X_given_theta_minus * P_theta_minus) / (P_X * risk_boost)
    R_U_minus = 1 / (1 + math.exp(-R_U_minus))

    return R_U_minus


# 计算用户行为分数
def calculate_behavior_scores(user, reputations, risks, alpha=0.5, beta=0.5):
    scores = (alpha * reputations - beta * risks) * 10
    scores = max(0.0, min(scores, 1.0))
    smoothed_behavior_score = 0.8 * user["behavior_score"] + 0.2 * scores
    # print("behavior scores:", smoothed_behavior_score)
    return smoothed_behavior_score


# 计算网关信誉值和风险值
def calculate_gateway_values(user, gateway):
    reputation = (user["ACF"] * user["HBHS"] + gateway["User_Num"] * gateway["GRV"]) / (
            user["ACF"] + gateway["User_Num"])
    risk = (user["ACF"] * user["HBHR"] + gateway["User_Num"] * gateway["GRR"]) / (
            user["ACF"] + gateway["User_Num"])
    reputation = 1 / (1 + math.exp(-reputation))
    risk = 0.5 / (1 + math.exp(-risk))
    return reputation, risk


# 更新用户状态
def update_user_stats(user, gateway, delta, sigma):
    # 计算信誉值、风险值
    user["HBHS"] = calculate_reputation(user, gateway, delta)
    user["HBHR"] = calculate_risk(user, gateway, sigma)

    # 计算行为分数
    behavior_score_new = calculate_behavior_scores(user, user["HBHS"], user["HBHR"])
    user["behavior_score"] = behavior_score_new

    # 更新网关值
    gateway["GACC"] = gateway["GACC"] + 1
    gateway["GRV"], gateway["GRR"] = calculate_gateway_values(user, gateway)
    return user, gateway


# 更新用户访问等级
def update_capl(user, behavior_score_old):
    # 确定当前 CAPL 的范围区间
    capl_ranges = [(0, 9), (10, 19), (20, 29)]
    for a, b in capl_ranges:
        if a <= user["CAPL"] <= b:
            break
    else:
        print("CAPL value error: out of range")
        return user["CAPL"]  # 返回当前权限值，防止逻辑中断

    # 计算评分变化
    behavior_score_change = user["behavior_score"] - behavior_score_old
    # print('user score:', user['behavior_score'])
    # print('behavior score change:', behavior_score_change)

    # 根据评分变化调整权限
    if abs(behavior_score_change) >= 0.05:
        AL_new = user["CAPL"] + 1 if behavior_score_change > 0 else user["CAPL"] - 1
    elif math.floor(user["CARL"] / 10) > math.floor(user["CAPL"] / 10):
        AL_new = user["CAPL"] - 10
    else:
        AL_new = user["CAPL"]

    # 检查其他调整条件
    if user["MTP"] > 0.1:
        AL_new -= 1
    if user["SACF"] / user["ACF"] > 0.05 and user["SACF"] != 1:
        AL_new -= 1

    # 限制权限级别在当前区间范围内
    return max(a, min(AL_new, b))


# 保存用户和网关信息
def save_user_and_gateway_to_csv(user, gateway, delta, sigma, filename="调参.csv"):
    # 存储字典数据到CSV
    fieldnames_user = list(user.keys())
    fieldnames_gateway = list(gateway.keys())
    fieldnames_delta = list(delta.keys())
    fieldnames_sigma = list(sigma.keys())

    fieldnames = fieldnames_user + fieldnames_gateway + fieldnames_delta + fieldnames_sigma  # 合并字段名

    # 检查文件是否存在
    file_exists = os.path.exists(filename)

    # 打开CSV文件，决定是写入新文件还是追加数据
    with open(filename, mode="a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        # 如果文件不存在，写入表头
        if not file_exists:
            writer.writeheader()

        # 合并user和gateway数据并写入
        merged_data = {**user, **gateway, **delta, **sigma}
        writer.writerow(merged_data)


def generate_deltas():
    # 步长为0.05的可能值
    values = [i * 0.05 for i in range(1, 21)]  # 从0.05到1.0，步长为0.05
    # 使用itertools生成所有可能的组合
    all_combinations = itertools.product(values, repeat=4)
    # 设置浮点数容忍范围
    tolerance = 1e-9
    # 筛选出和为1且每个元素不为0的组合
    valid_combinations = [
        combo for combo in all_combinations
        if abs(sum(combo) - 1) < tolerance and all(x > 0 for x in combo)
    ]

    # 迭代生成不重复的组合
    for combo in valid_combinations:
        # 返回一个字典
        yield {"P_AS": combo[0], "P_ACS": combo[1], "P_LAF": combo[2], "f_RL1": combo[3]}


def generate_sigma():
    # 步长为0.05的可能值
    values = [i * 0.05 for i in range(1, 21)]  # 从0.05到1.0，步长为0.05
    # 使用itertools生成所有可能的组合
    all_combinations = itertools.product(values, repeat=5)  # 因为sigma有5个参数
    # 设置浮点数容忍范围
    tolerance = 1e-9
    # 筛选出和为1且每个元素不为0的组合
    valid_combinations = [
        combo for combo in all_combinations
        if abs(sum(combo) - 1) < tolerance and all(x > 0 for x in combo)
    ]

    # 迭代生成不重复的组合
    for combo in valid_combinations:
        # 返回一个字典
        yield {"P_AF": combo[0], "P_ACF": combo[1], "P_SAC": combo[2], "f_RL": combo[3], "MTP": combo[4]}


# 敏感访问
def sensitive_resource(user):
    upper_bound = min((user["CAPL"] // 10 + 1) * 10 - 1, 29)
    user["CARL"] = random.randint(user["CAPL"] + 1, upper_bound)
    return user


# 越级访问
def leapfrog(user):
    if user["CAPL"] < 10:
        user["CARL"] = random.randint(10, 29)  # 如果 CAPL 在 0 到 9 之间，访问 10 到 29
    elif user["CAPL"] < 20:
        user["CARL"] = random.randint(20, 29)  # 如果 CAPL 在 10 到 19 之间，访问 20 到 29
    return user


# 越级访问和敏感信息访问
def sens_and_leap(user):
    # 敏感和越级访问
    if user["CAPL"] < 10:
        user["CARL"] = random.randint(user["CAPL"] + 1, 29)  # 如果 CAPL 在 0 到 9 之间，访问 10 到 29
    elif user["CAPL"] < 20:
        user["CARL"] = random.randint(user["CAPL"] + 1, 29)  # 如果 CAPL 在 10 到 19 之间，访问 20 到 29
    return user


# ddos攻击
def ddos_attack(user):
    # 攻击
    user["MTP"] = 1
    return user


# 设置初始用户和网关参数
def init_value(capl):
    user_data = {
        "AC": 1, "ASF": 1, "FAF": 0, "AUTH_TS": 0, "ACC": 1, "ACSF": 1, "FACF": 0, "AS_TS": 1, "CAPL": capl,
        "CARL": random.randint(0, capl - 5), "LAC": 1, "ACF": 1.0, "SACF": 1.0, "MTP": 0, "HBHS": 1, "HBHR": 0,
        "behavior_score": 0.791
    }
    gateway = {"GASF": 1, "GAC": 1, "GACSF": 1, "GACC": 1, "User_Num": 1, "GRV": 0.791, "GRR": 0}
    delta = {"P_AS": 0.012, "P_ACS": 0.945, "P_LAF": 0.031, "f_RL1": 0.012}
    sigma = {"P_AF": 0.036, "P_ACF": 0.017, "P_SAC": 0.039, "f_RL2": 0.004, "MTP_index": 0.903}
    return user_data, gateway, delta, sigma


def get_attack_rounds(k, _time_type):
    if time_type == "INT":
        attack_rounds = [20, 23, 26, 29]
    elif time_type is None:
        if attack_type == 'RS+ATK+PE(2)':
            attack_rounds = list(range(18 + attack_type_list.index(attack_type), k, 1))
        else:
            attack_rounds = list(range(19 + attack_type_list.index(attack_type), k, 1))
    else:
        attack_rounds = None
        print(time_type, 'error2')
    return attack_rounds


def attack(i, user1, attack_type):
    # 定义攻击类型与对应的处理函数
    attack_map = {
        'NAcc': lambda: user1.update({"CARL": random.randint(0, user1["CAPL"])}),
        'RS': lambda: sensitive_resource(user1),
        'ATK': lambda: ddos_attack(user1),
        'PE': lambda: leapfrog(user1),
        'RS+ATK': lambda: ddos_attack(sensitive_resource(user1)),
        'RS+PE': lambda: sens_and_leap(user1),
        'ATK+PE': lambda: leapfrog(ddos_attack(user1)),
        'RS+ATK+PE': lambda: sens_and_leap(ddos_attack(user1)),
        'RS+ATK+PE(2)': lambda: ddos_attack(sens_and_leap(user1)) if i in [20, 26] else ddos_attack(user1) if i in [23,
                                                                                                                    29] else user1,
        'RS+ATK(2)': lambda: sensitive_resource(user1) if i in [20, 26] else ddos_attack(user1) if i in [23,
                                                                                                         29] else user1
    }

    # 调用对应的攻击类型处理函数
    if attack_type in attack_map:
        attack_map[attack_type]()
        return user1  # 执行映射到的攻击操作
    else:
        print(attack_type, 'error3')  # 错误处理
        return None


def update_user_state(user1, gateway, delta, sigma):
    if math.floor(user1["CAPL"] / 10) < math.floor(user1["CARL"] / 10) or user1["MTP"] >= 0.3 or user1[
        "ACF"] > 100 * 1e9:
        # 更新用户状态
        user1["AS_TS"] = int(time.perf_counter() * 1e9)
        user1["ACC"] = user1["ACC"] + 1
        user1["FACF"] = user1["ACC"] - user1["ACSF"]
        user1["ACF"] = user1["ACC"] / (user1["AS_TS"] - user1["AUTH_TS"])
        user1["SACF"] = (user1["ACSF"] - user1["LAC"]) / (user1["AS_TS"] - user1["AUTH_TS"])
        # 更新信誉、风险和行为分数
        user1, gateway = update_user_stats(user1, gateway, delta, sigma)
    else:
        # 更新用户状态
        user1["AS_TS"] = int(time.perf_counter() * 1e9)
        user1["ACC"] = user1["ACC"] + 1
        user1["ACSF"] = user1["ACSF"] + 1
        user1["FACF"] = user1["ACC"] - user1["ACSF"]
        user1["ACF"] = user1["ACC"] / (user1["AS_TS"] - user1["AUTH_TS"])
        if user1["CAPL"] >= user1["CARL"]:
            user1["LAC"] = user1["LAC"] + 1
        else:
            user1["LAC"] = user1["LAC"]
        user1["SACF"] = (user1["ACSF"] - user1["LAC"]) / (user1["AS_TS"] - user1["AUTH_TS"])
        gateway["GACSF"] = gateway["GACSF"] + 1
        # 更新信誉、风险和行为分数
        user1, gateway = update_user_stats(user1, gateway, delta, sigma)
    return user1, gateway


def user_access(_time_type, _user_type, _attack_type):
    k, i = 50, 0
    user_type_config = {'RU': 5, 'PU': 15, 'Admin': 25}
    capl = user_type_config.get(user_type, None)
    if capl is None:
        print(user_type, 'error1')
        return None, None

    user1, gateway, delta, sigma = init_value(capl)
    user1["AUTH_TS"] = int(time.perf_counter() * 1e9)
    attack_type_list = ['NAcc', 'RS', 'ATK', 'PE', 'RS+ATK', 'RS+PE', 'ATK+PE', 'RS+ATK+PE', 'RS+ATK+PE(2)']
    prev_behavior_score = user1["behavior_score"]  # 初始化上一轮的用户行为分数
    while i < k:
        if time_type is None:
            save_user_and_gateway_to_csv(user1, gateway, delta, sigma,
                                         "D:\\01_08_零信任网元\\数据处理\\" + user_type + " " + attack_type + ".csv")
        else:
            save_user_and_gateway_to_csv(user1, gateway, delta, sigma,
                                         "D:\\01_08_零信任网元\\数据处理\\" + time_type + " " + user_type + " " + attack_type + ".csv")
        attack_rounds = get_attack_rounds(k, time_type)

        if i in attack_rounds:
            user1["CAPL"] = update_capl(user1, prev_behavior_score)
            user1 = attack(i, user1, attack_type)
            user1, gateway = update_user_state(user1, gateway, delta, sigma)
        else:
            user1["CAPL"] = update_capl(user1, prev_behavior_score)
            user1["CARL"] = random.randint(0, user1["CAPL"])
            user1["MTP"] = 0
            user1, gateway = update_user_state(user1, gateway, delta, sigma)
        i = i + 1

        # if i == 25:
        #     a = user1['behavior_score']
        # if i == 29:
        #     b = user1['behavior_score']
        #     # save_user_and_gateway_to_csv({}, delta, sigma,
        #     #                              {"Difference in behavior score scores": (b - a), 'behavior score': a},
        #     #                              "D:\\01_08_零信任网元\\数据处理\\result.csv")
        prev_behavior_score = user1["behavior_score"]
    return user1, gateway  # , float((b - a) / 4)


if __name__ == "__main__":
    time_type_list = ['INT', None]
    user_type_list = ['RU', 'PU', 'Admin']

    for time_type in time_type_list:
        for user_type in user_type_list:
            if user_type == 'Admin':
                attack_type_list = ['NAcc', 'RS', 'ATK', 'RS+ATK']
                for attack_type in attack_type_list:
                    user_access(time_type, user_type, attack_type)
            else:
                attack_type_list = ['NAcc', 'RS', 'ATK', 'PE', 'RS+ATK', 'RS+PE', 'ATK+PE', 'RS+ATK+PE', 'RS+ATK+PE(2)']
                for attack_type in attack_type_list:
                    user_access(time_type, user_type, attack_type)

    user_access('INT', 'Admin', 'RS+ATK(2)')
