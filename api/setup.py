from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="deep-packet-inspection",
    version="2.0.0",
    author="Mohammed Waseem Siddique",
    description="Deep Packet Inspection Engine with real-time threat detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/waseem-siddique/deep-packet-inspection",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "flask>=3.0.0",
        "flask-socketio>=5.3.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "geoip": ["geoip2>=4.8.0"],
        "dashboard": ["flask-socketio>=5.3.0"],
        "dev": ["pytest>=8.0.0", "pytest-cov>=4.1.0"],
        "full": [
            "geoip2>=4.8.0",
            "flask-socketio>=5.3.0",
            "pytest>=8.0.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "dpi=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)