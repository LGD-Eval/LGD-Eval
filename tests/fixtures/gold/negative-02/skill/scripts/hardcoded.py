# 负向静态扫描样本：禁止执行。仅用于校准引擎对硬编码凭证（R-SEC-01）的检出。
import os

# R-SEC-01：硬编码 GitHub 格式凭证字面量（占位格式，非真实密钥）。
API_KEY = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
