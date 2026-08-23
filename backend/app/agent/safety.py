from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    code: str | None = None
    message: str | None = None


class ChatSafetyGuard:
    _blocked_patterns = (
        re.compile(r"忽略.{0,12}(系统|安全|规则|指令)"),
        re.compile(r"(泄露|显示|输出).{0,8}(系统提示|system prompt)", re.IGNORECASE),
        re.compile(r"(执行|运行).{0,8}(shell|终端|系统命令|任意\s*sql)", re.IGNORECASE),
        re.compile(r"(自动|直接).{0,6}(修改|删除|下发).{0,12}(防火墙|配置)"),
    )

    def inspect(self, message: str) -> SafetyDecision:
        normalized = " ".join(message.split())
        for pattern in self._blocked_patterns:
            if pattern.search(normalized):
                return SafetyDecision(
                    allowed=False,
                    code="UNSAFE_INSTRUCTION",
                    message=(
                        "请求试图绕过系统边界或执行未授权操作。系统只允许查询、检测、报告筛选和标准检索。"
                    ),
                )
        return SafetyDecision(allowed=True)
