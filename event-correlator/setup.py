#!/usr/bin/env python3
"""
Setup script for Event Correlation Engine
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="event-correlator",
    version="1.0.0",
    author="Security-Enhancement Team",
    author_email="security@company.com",
    description="A lightweight, production-ready event correlation engine for security monitoring",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/security-enhancement/event-correlator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "event-correlator=correlator:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.jsonl", "*.md"],
    },
    keywords="security, monitoring, correlation, events, detection, siem",
    project_urls={
        "Bug Reports": "https://github.com/security-enhancement/event-correlator/issues",
        "Source": "https://github.com/security-enhancement/event-correlator",
        "Documentation": "https://github.com/security-enhancement/event-correlator/blob/main/README.md",
    },
)