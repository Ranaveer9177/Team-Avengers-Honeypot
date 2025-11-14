"""Setup script for Multi-Service Honeypot System"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="honeypot-system",
    version="1.1.0",
    author="Team Avengers",
    author_email="",
    description="Multi-Service Honeypot System with Advanced Attack Detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Ranaveer9177/Team-Avengers-Honeypot",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "flake8>=6.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "honeypot-server=unified_honeypot:main",
            "honeypot-dashboard=app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/*.html", "config/*.json"],
    },
    zip_safe=False,
)
