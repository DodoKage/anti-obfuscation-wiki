#!/usr/bin/env python3
"""
MBA (Mixed Boolean-Arithmetic) 对抗: 混淆器 vs 简化器

攻击方: 将 a+b 等简单运算替换为等价的复杂 MBA 表达式
防御方: 通过真值表穷举/代数简化/Z3求解还原原始表达式
"""

import random
import itertools


# ============================================================
#  攻击方: MBA 混淆器
# ============================================================

class MBAObfuscator:
    """将简单运算替换为等价的复杂 MBA 表达式"""

    # 8 个布尔基向量 (2 变量)
    # x:  0 0 1 1
    # y:  0 1 0 1
    BASIS = {
        'x & y':    (0, 0, 0, 1),
        'x & ~y':   (0, 0, 1, 0),
        '~x & y':   (0, 1, 0, 0),
        '~x & ~y':  (1, 0, 0, 0),
        'x | y':    (0, 1, 1, 1),
        'x | ~y':   (1, 0, 1, 1),
        '~x | y':   (1, 1, 0, 1),
        '~x | ~y':  (1, 1, 1, 0),
        'x ^ y':    (0, 1, 1, 0),
        '1':        (1, 1, 1, 1),
    }

    TARGETS = {
        'x + y':    (0, 1, 1, 2),
        'x - y':    (0, -1, 1, 0),
        'x ^ y':    (0, 1, 1, 0),
        'x & y':    (0, 0, 0, 1),
        'x | y':    (0, 1, 1, 1),
        '~x':       (1, 1, 0, 0),
        '~y':       (1, 0, 1, 0),
        'x':        (0, 0, 1, 1),
        'y':        (0, 1, 0, 1),
    }

    def obfuscate(self, target_name, complexity=3):
        """将目标表达式替换为等价的 MBA 表达式"""
        if target_name not in self.TARGETS:
            raise ValueError(f"Unknown target: {target_name}")

        target_vec = self.TARGETS[target_name]

        # 随机选取 complexity 个基向量
        basis_names = list(self.BASIS.keys())
        selected = random.sample(basis_names, min(complexity, len(basis_names)))

        # 构造系数方程: sum(coeff[i] * basis[i]) = target (mod 256 for 8-bit)
        # 使用随机系数搜索
        coefficients = self._find_coefficients(target_vec, selected)

        if coefficients is None:
            # 回退到已知的精确替换
            return self._known_substitution(target_name)

        # 构造 MBA 表达式字符串
        terms = []
        for coeff, basis_name in zip(coefficients, selected):
            if coeff == 0:
                continue
            if coeff == 1:
                terms.append(f"({basis_name})")
            elif coeff == -1:
                terms.append(f"-({basis_name})")
            else:
                terms.append(f"{coeff}*({basis_name})")

        return ' + '.join(terms) if terms else '0'

    def _find_coefficients(self, target, selected_bases, bits=8):
        """搜索系数使得线性组合匹配目标"""
        basis_vecs = [self.BASIS[name] for name in selected_bases]
        n = len(basis_vecs)
        modulus = 1 << bits

        for attempt in range(10000):
            coeffs = [random.randint(-50, 50) for _ in range(n)]
            match = True
            for col in range(4):
                total = sum(c * basis_vecs[i][col] for i, c in enumerate(coeffs))
                if (total % modulus) != (target[col] % modulus):
                    match = False
                    break
            if match:
                return coeffs

        return None

    def _known_substitution(self, target_name):
        """已知的精确 MBA 替换"""
        subs = {
            'x + y': '(x ^ y) + 2*(x & y)',
            'x - y': '(x ^ y) - 2*(~x & y)',
            'x ^ y': '(~x & y) | (x & ~y)',
            'x & y': '~(~x | ~y)',
            'x | y': '(x & y) | (x ^ y)',
        }
        return subs.get(target_name, target_name)

    def multi_layer(self, target_name, layers=2, complexity=3):
        """多层嵌套 MBA 混淆"""
        expr = self.obfuscate(target_name, complexity)
        for _ in range(layers - 1):
            # 对子表达式再次混淆
            if '+' in expr:
                parts = expr.split(' + ', 1)
                sub_obf = self.obfuscate('x + y', complexity)
                expr = f"/* layer */ ({expr})"
        return expr


# ============================================================
#  防御方: MBA 简化器
# ============================================================

class MBASimplifier:
    """将复杂 MBA 表达式还原为简单形式"""

    KNOWN_EXPRS = {
        'x + y':  lambda x, y: (x + y) & 0xFF,
        'x - y':  lambda x, y: (x - y) & 0xFF,
        'x * y':  lambda x, y: (x * y) & 0xFF,
        'x ^ y':  lambda x, y: (x ^ y) & 0xFF,
        'x & y':  lambda x, y: (x & y) & 0xFF,
        'x | y':  lambda x, y: (x | y) & 0xFF,
        '~x':     lambda x, y: (~x) & 0xFF,
        '~y':     lambda x, y: (~y) & 0xFF,
        'x':      lambda x, y: x & 0xFF,
        'y':      lambda x, y: y & 0xFF,
        '0':      lambda x, y: 0,
        '-x':     lambda x, y: (-x) & 0xFF,
        '-y':     lambda x, y: (-y) & 0xFF,
        'x + 1':  lambda x, y: (x + 1) & 0xFF,
        'x - 1':  lambda x, y: (x - 1) & 0xFF,
        '2*x':    lambda x, y: (2 * x) & 0xFF,
        '2*y':    lambda x, y: (2 * y) & 0xFF,
    }

    def simplify_by_truth_table(self, expr_str, bits=8):
        """
        方法 1: 真值表穷举
        计算表达式在所有输入下的值，与已知简单表达式比较
        """
        modulus = 1 << bits

        # 计算 MBA 表达式的真值表
        expr_table = []
        for x in range(modulus):
            for y in range(modulus):
                try:
                    result = eval(expr_str, {'x': x, 'y': y, '__builtins__': {}}) & (modulus - 1)
                except:
                    return None
                expr_table.append(result)

        # 与已知表达式比较
        for name, func in self.KNOWN_EXPRS.items():
            known_table = [func(x, y) for x in range(modulus) for y in range(modulus)]
            if expr_table == known_table:
                return name

        return None

    def simplify_by_sampling(self, expr_str, samples=1000, bits=8):
        """
        方法 2: 随机采样验证 (快速但非100%准确)
        """
        modulus = 1 << bits
        test_pairs = [(random.randint(0, modulus-1), random.randint(0, modulus-1))
                      for _ in range(samples)]

        for name, func in self.KNOWN_EXPRS.items():
            match = True
            for x, y in test_pairs:
                try:
                    expr_val = eval(expr_str, {'x': x, 'y': y, '__builtins__': {}}) & (modulus - 1)
                    known_val = func(x, y)
                    if expr_val != known_val:
                        match = False
                        break
                except:
                    match = False
                    break
            if match:
                return name

        return None

    def simplify_algebraic(self, expr_str):
        """
        方法 3: 代数重写规则
        """
        rules = [
            # a ^ b 等价形式
            ('(~x & y) | (x & ~y)', 'x ^ y'),
            ('(x | y) & (~x | ~y)', 'x ^ y'),
            ('(x | y) & ~(x & y)', 'x ^ y'),

            # a & b 等价形式
            ('~(~x | ~y)', 'x & y'),
            ('(x + y) - (x | y)', 'x & y'),

            # a | b 等价形式
            ('~(~x & ~y)', 'x | y'),
            ('(x & y) | (x ^ y)', 'x | y'),
            ('(x + y) - (x & y)', 'x | y'),

            # a + b 等价形式
            ('(x ^ y) + 2*(x & y)', 'x + y'),
            ('(x | y) + (x & y)', 'x + y'),

            # a - b 等价形式
            ('(x ^ y) - 2*(~x & y)', 'x - y'),
        ]

        normalized = expr_str.replace(' ', '')
        for pattern, replacement in rules:
            if normalized == pattern.replace(' ', ''):
                return replacement

        return None


# ============================================================
#  对抗演示
# ============================================================

def verify_equivalence(original_name, mba_expr, bits=8):
    """验证 MBA 表达式与原始表达式是否等价"""
    modulus = 1 << bits
    original_func = MBASimplifier.KNOWN_EXPRS.get(original_name)
    if not original_func:
        return False

    for x in range(modulus):
        for y in range(modulus):
            try:
                mba_val = eval(mba_expr, {'x': x, 'y': y, '__builtins__': {}}) & (modulus - 1)
            except:
                return False
            orig_val = original_func(x, y)
            if mba_val != orig_val:
                return False
    return True


def battle():
    """攻防对抗"""
    print("=" * 70)
    print("  MBA 对抗: 混淆器 vs 简化器")
    print("=" * 70)

    obfuscator = MBAObfuscator()
    simplifier = MBASimplifier()

    targets = ['x + y', 'x - y', 'x ^ y', 'x & y', 'x | y']

    for target in targets:
        print(f"\n{'─'*70}")
        print(f"[目标] {target}")
        print(f"{'─'*70}")

        # 攻击方: 混淆
        mba_expr = obfuscator.obfuscate(target, complexity=4)
        print(f"  [攻击方] MBA 混淆: {mba_expr}")

        # 验证混淆正确性
        is_valid = verify_equivalence(target, mba_expr)
        print(f"  [验证]   混淆正确性: {'VALID' if is_valid else 'INVALID'}")

        if not is_valid:
            # 使用已知替换
            mba_expr = obfuscator._known_substitution(target)
            print(f"  [回退]   使用已知替换: {mba_expr}")
            is_valid = verify_equivalence(target, mba_expr)
            print(f"  [验证]   混淆正确性: {'VALID' if is_valid else 'INVALID'}")

        # 防御方: 简化
        print()

        # 方法 1: 真值表
        result1 = simplifier.simplify_by_truth_table(mba_expr)
        status1 = "CRACKED" if result1 == target else ("PARTIAL" if result1 else "FAILED")
        print(f"  [防御方] 真值表穷举: {result1 or '无法简化':20s} [{status1}]")

        # 方法 2: 采样
        result2 = simplifier.simplify_by_sampling(mba_expr)
        status2 = "CRACKED" if result2 == target else ("PARTIAL" if result2 else "FAILED")
        print(f"  [防御方] 随机采样:   {result2 or '无法简化':20s} [{status2}]")

        # 方法 3: 代数重写
        result3 = simplifier.simplify_algebraic(mba_expr)
        status3 = "CRACKED" if result3 == target else ("PARTIAL" if result3 else "FAILED")
        print(f"  [防御方] 代数重写:   {result3 or '无法简化':20s} [{status3}]")

        # 判定
        cracked = any(r == target for r in [result1, result2, result3])
        print(f"\n  {'>>> 防御方胜: 成功还原!' if cracked else '>>> 攻击方胜: 抵抗了所有简化!'}")

    # 高强度对抗
    print(f"\n{'='*70}")
    print("  高强度对抗: 已知精确替换")
    print(f"{'='*70}")

    hard_cases = [
        ('x + y', '(x ^ y) + 2*(x & y)'),
        ('x + y', '(x | y) + (x & y)'),
        ('x - y', '(x ^ y) - 2*(~x & y)'),
        ('x ^ y', '(x | y) & ~(x & y)'),
        ('x & y', '~(~x | ~y)'),
    ]

    for original, mba in hard_cases:
        result = simplifier.simplify_by_truth_table(mba)
        status = "CRACKED" if result == original else "FAILED"
        print(f"  {mba:40s} → {result or '?':10s} [{status}]")


if __name__ == '__main__':
    battle()
